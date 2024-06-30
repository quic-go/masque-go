package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/dunglas/httpsfv"
	"github.com/yosida95/uritemplate/v3"
)

const (
	requestProtocol = "connect-udp"
	capsuleHeader   = "Capsule-Protocol"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(1))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

type proxyEntry struct {
	str  http3.Stream
	conn *net.UDPConn
}

type Proxy struct {
	http3.Server

	// Template is the URI template that clients will use to configure this UDP proxy.
	Template *uritemplate.Template

	// DialTarget is called when the proxy needs to open a new UDP socket to the target server.
	// It must return a connected UDP socket.
	// TODO(#3): support unconnected sockets.
	DialTarget func(context.Context, string) (*net.UDPConn, error)

	closed atomic.Bool

	mx       sync.Mutex
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	conns    map[proxyEntry]struct{}
}

func (s *Proxy) Upgrade(w http.ResponseWriter, r *http.Request) error {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if r.Proto != requestProtocol {
		w.WriteHeader(http.StatusNotImplemented)
		return fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	// TODO: check :authority
	capsuleHeaderValues, ok := r.Header[capsuleHeader]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("missing Capsule-Protocol header")
	}
	item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("invalid capsule header value: %s", r.Header[capsuleHeader])
	}
	if v, ok := item.Value.(int64); !ok || v != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("incorrect capsule header value: %d", v)
	}

	match := s.Template.Match(r.URL.String())
	targetHostEncoded := match.Get(uriTemplateTargetHost).String()
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHostEncoded == "" || targetPortStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("expected target_host and target_port")
	}
	targetHost, err := url.QueryUnescape(targetHostEncoded)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return fmt.Errorf("failed to decode target_host: %w", err)
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return errors.New("failed to decode target_port")
	}
	w.Header().Set(capsuleHeader, capsuleProtocolHeaderValue)

	dst := fmt.Sprintf("%s:%d", targetHost, targetPort)

	var conn *net.UDPConn
	if s.DialTarget == nil {
		addr, err := net.ResolveUDPAddr("udp", dst)
		if err != nil {
			// TODO: set proxy-status header (might want to use structured headers)
			w.WriteHeader(http.StatusGatewayTimeout)
			return fmt.Errorf("failed to resolve target address: %w", err)
		}
		conn, err = net.DialUDP("udp", nil, addr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}
	} else {
		conn, err = s.DialTarget(r.Context(), dst)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}
	}
	str := w.(http3.HTTPStreamer).HTTPStream()

	s.mx.Lock()
	if s.closed.Load() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		str.Close()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if s.conns == nil {
		s.conns = make(map[proxyEntry]struct{})
	}
	s.conns[proxyEntry{str: str, conn: conn}] = struct{}{}
	s.refCount.Add(3)
	s.mx.Unlock()

	go func() {
		defer s.refCount.Done()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		conn.Close()
	}()
	go func() {
		defer s.refCount.Done()
		if err := s.proxyConnReceive(conn, str); err != nil && !s.closed.Load() {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		conn.Close()
	}()
	go func() {
		defer s.refCount.Done()
		// discard all capsules sent on the request stream
		if err := skipCapsules(quicvarint.NewReader(str)); err == io.EOF {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
		conn.Close()
	}()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str http3.Stream) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str http3.Stream) error {
	b := make([]byte, 1500)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return err
		}
		if err := str.SendDatagram(b[:n]); err != nil {
			return err
		}
	}
}

func (s *Proxy) Close() error {
	s.closed.Store(true)
	err := s.Server.Close()
	s.mx.Lock()
	for entry := range s.conns {
		entry.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		entry.str.Close()
		entry.conn.Close()
	}
	s.conns = nil
	s.mx.Unlock()
	s.refCount.Wait()
	return err
}

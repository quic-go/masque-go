package masque

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

type proxyEntry struct {
	str  http3.Stream
	conn *net.UDPConn
}

type Proxy struct {
	closed atomic.Bool

	mx       sync.Mutex
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	conns    map[proxyEntry]struct{}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
	if s.closed.Load() {
		return net.ErrClosed
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		// TODO: set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		// TODO: set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}
	defer conn.Close()

	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	if s.closed.Load() {
		return net.ErrClosed
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	w.Header().Set(capsuleHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

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
	s.mx.Unlock()

	var wg sync.WaitGroup
	s.refCount.Add(3)
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer s.refCount.Done()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		defer s.refCount.Done()
		if err := s.proxyConnReceive(conn, str); err != nil && !s.closed.Load() {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		defer s.refCount.Done()
		// discard all capsules sent on the request stream
		if err := skipCapsules(quicvarint.NewReader(str)); err == io.EOF {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
		conn.Close()
	}()
	wg.Wait()
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
	s.mx.Lock()
	for entry := range s.conns {
		entry.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		entry.str.Close()
		entry.conn.Close()
	}
	s.conns = nil
	s.mx.Unlock()
	s.refCount.Wait()
	return nil
}

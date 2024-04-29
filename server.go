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
	"sync/atomic"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
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

type Server struct {
	http3.Server

	Template *uritemplate.Template

	Allow func(context.Context, *net.UDPAddr) bool
}

func (s *Server) Upgrade(w http.ResponseWriter, r *http.Request) error {
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
	addr, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		// TODO: set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
	}
	if s.Allow != nil && !s.Allow(r.Context(), addr) {
		w.WriteHeader(http.StatusForbidden)
		return errors.New("forbidden")
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	str := w.(http3.HTTPStreamer).HTTPStream()
	go s.handleConn(conn, str)
	return nil
}

func (s *Server) handleConn(conn *net.UDPConn, str http3.Stream) {
	var closing atomic.Bool
	go func() {
		err := s.proxyConnSend(conn, str)
		if err != nil && !closing.Load() {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		conn.Close()
	}()
	go func() {
		err := s.proxyConnReceive(conn, str)
		if err != nil && !closing.Load() {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		conn.Close()
	}()

	// discard all capsules sent on the request stream
	err := skipCapsules(quicvarint.NewReader(str))
	closing.Store(true)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf("reading from request stream failed: %v", err)
	}
	str.Close()
	conn.Close()
}

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}

func (s *Server) proxyConnSend(conn *net.UDPConn, str http3.Stream) error {
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

func (s *Server) proxyConnReceive(conn *net.UDPConn, str http3.Stream) error {
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

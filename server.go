package masque

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	requestProtocol = "connect-udp"
	capsuleHeader   = "capsule-protocol"
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
		return fmt.Errorf("expected CONNECT request, got %s", r.Method)
	}
	if r.Proto != requestProtocol {
		return fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	// TODO: check :authority
	// TODO: check for capsule protocol header

	match := s.Template.Match(r.URL.String())
	targetHostEncoded := match.Get(uriTemplateTargetHost).String()
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHostEncoded == "" || targetPortStr == "" {
		return fmt.Errorf("expected target_host and target_port")
	}
	targetHost, err := url.QueryUnescape(targetHostEncoded)
	if err != nil {
		return fmt.Errorf("failed to decode target_host: %w", err)
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
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
	go func() {
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
	}()
	go func() {
		if err := s.proxyConnReceive(conn, str); err != nil {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
	}()
	w.WriteHeader(http.StatusOK)
	select {} // TODO: return
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

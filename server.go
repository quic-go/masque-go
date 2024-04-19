package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	protocolHeader = "connect-udp"
	capsuleHeader  = "capsule-protocol"
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
	if r.Proto != protocolHeader {
		return fmt.Errorf("unexpected protocol: %s", r.Proto)
	}
	// TODO: check :authority
	// TODO: check for capsule protocol header

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
		return fmt.Errorf("failed to decode target_port: %w", err)
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

	w.WriteHeader(http.StatusOK)

	return nil
}

package masque_test

import (
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/stretchr/testify/require"
)

const requestProtocol = "connect-udp"

func TestUpgradeFailures(t *testing.T) {
	mux := http.NewServeMux()
	s := masque.Server{
		Server: http3.Server{
			Handler: mux,
		},
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
	}

	t.Run("wrong request method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque", nil)
		err := s.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "expected CONNECT request, got GET")
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque", nil)
		req.Method = http.MethodConnect
		req.Proto = "not-connect-udp"
		err := s.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "unexpected protocol: not-connect-udp")
	})

	t.Run("missing target host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque?h=&p=1234", nil)
		req.Method = http.MethodConnect
		req.Proto = requestProtocol
		err := s.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "expected target_host and target_port")
	})

	t.Run("invalid target port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque?h=localhost&p=foobar", nil)
		req.Method = http.MethodConnect
		req.Proto = requestProtocol
		err := s.Upgrade(httptest.NewRecorder(), req)
		require.EqualError(t, err, "failed to decode target_port")
	})
}

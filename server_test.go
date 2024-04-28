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
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "expected CONNECT request, got GET")
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque", nil)
		req.Method = http.MethodConnect
		req.Proto = "not-connect-udp"
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "unexpected protocol: not-connect-udp")
		require.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("missing target host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque?h=&p=1234", nil)
		req.Method = http.MethodConnect
		req.Proto = requestProtocol
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "expected target_host and target_port")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid target port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:1234/masque?h=localhost&p=foobar", nil)
		req.Method = http.MethodConnect
		req.Proto = requestProtocol
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "failed to decode target_port")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

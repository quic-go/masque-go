package masque_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
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

	newRequest := func(target string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Method = http.MethodConnect
		req.Proto = requestProtocol
		req.Header.Add("Capsule-Protocol", "1")
		return req
	}

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Method = http.MethodHead
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto = "not-connect-udp"
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "unexpected protocol: not-connect-udp")
		require.Equal(t, http.StatusNotImplemented, rec.Code)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Del("Capsule-Protocol")
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "🤡")
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "invalid capsule header value: [🤡]")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "2")
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "incorrect capsule header value: 2")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing target host", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=&p=1234")
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "expected target_host and target_port")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid target port", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=foobar")
		rec := httptest.NewRecorder()
		require.EqualError(t, s.Upgrade(rec, req), "failed to decode target_port")
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

package masque

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestRequestParsing(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}")

	t.Run("valid request for a hostname", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, r.Target, "localhost:1337")
	})

	t.Run("valid request for an IPv4 address", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=1.2.3.4&p=9999")
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, r.Target, "1.2.3.4:9999")
	})

	t.Run("valid request for an IPv6 address", func(t *testing.T) {
		req := newRequest(fmt.Sprintf("https://localhost:1234/masque?h=%s&p=1234", escape("::1")))
		r, err := ParseRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, r.Target, "[::1]:1234")
	})

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Method = http.MethodHead
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto = "not-connect-udp"
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "unexpected protocol: not-connect-udp")
		require.Equal(t, http.StatusNotImplemented, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong :authority", func(t *testing.T) {
		req := newRequest("https://quic-go.net:1234/masque")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "host in :authority (quic-go.net:1234) does not match template host (localhost:1234)")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Del("Capsule-Protocol")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "🤡")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "invalid capsule header value: [🤡]")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value type", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "1")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value type: int64")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		v, err := httpsfv.Marshal(httpsfv.NewItem(false))
		require.NoError(t, err)
		req.Header.Set("Capsule-Protocol", v)
		_, err = ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value: false")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing target host", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=&p=1234")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "expected target_host and target_port")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid target port", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=foobar")
		_, err := ParseRequest(req, template)
		require.ErrorContains(t, err, "failed to decode target_port")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})
}

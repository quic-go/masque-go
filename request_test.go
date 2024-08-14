package masque

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestRequestParsing(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}")

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

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "2")
		_, err := ParseRequest(req, template)
		require.EqualError(t, err, "incorrect capsule header value: 2")
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

func TestPathFromTemplate(t *testing.T) {
	for _, tc := range []struct {
		name, template, expected string
	}{
		{
			"variables as URL parameters",
			"https://localhost:1234/masque?h={target_host}&p={target_port}",
			"/masque",
		},
		{
			"variables in URL paths",
			"https://localhost:1234/masque/{target_host}/{target_port}",
			"/masque/", // needs to have a trailing /
		},
		{
			"variables in URL paths, no trailing /",
			"https://localhost:1234/masque/{target_host}/{target_port}/",
			"/masque/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			temp := uritemplate.MustNew(tc.template)
			path, err := PathFromTemplate(temp)
			require.NoError(t, err)
			require.Equal(t, tc.expected, path)
		})
	}
}

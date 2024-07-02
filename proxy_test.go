package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"go.uber.org/mock/gomock"
)

func scaleDuration(d time.Duration) time.Duration {
	if os.Getenv("CI") != "" {
		return 5 * d
	}
	return d
}

func newRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Method = http.MethodConnect
	req.Proto = requestProtocol
	req.Header.Add("Capsule-Protocol", "1")
	return req
}

type http3ResponseWriter struct {
	http.ResponseWriter
	str http3.Stream
}

var _ http3.HTTPStreamer = &http3ResponseWriter{}

func (s *http3ResponseWriter) HTTPStream() http3.Stream { return s.str }

func TestUpgradeFailures(t *testing.T) {
	s := Proxy{
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
	}

	t.Run("wrong request method", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Method = http.MethodHead
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "expected CONNECT request, got HEAD")
		require.Equal(t, http.StatusMethodNotAllowed, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("wrong protocol", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Proto = "not-connect-udp"
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "unexpected protocol: not-connect-udp")
		require.Equal(t, http.StatusNotImplemented, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Del("Capsule-Protocol")
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "missing Capsule-Protocol header")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "🤡")
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "invalid capsule header value: [🤡]")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid Capsule-Protocol header value", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque")
		req.Header.Set("Capsule-Protocol", "2")
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "incorrect capsule header value: 2")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("missing target host", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=&p=1234")
		_, err := s.ParseRequest(req)
		require.EqualError(t, err, "expected target_host and target_port")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})

	t.Run("invalid target port", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=foobar")
		_, err := s.ParseRequest(req)
		require.ErrorContains(t, err, "failed to decode target_port")
		require.Equal(t, http.StatusBadRequest, err.(*RequestParseError).HTTPStatus)
	})
}

func TestProxyCloseProxiedConn(t *testing.T) {
	testDone := make(chan struct{})
	defer close(testDone)

	remoteServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	s := Proxy{
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
	}
	req := newRequest(fmt.Sprintf("https://localhost:1234/masque?h=localhost&p=%d", remoteServerConn.LocalAddr().(*net.UDPAddr).Port))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	str := NewMockStream(gomock.NewController(t))
	str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		return []byte("foo"), nil
	})
	// This datagram is received after the connection is closed.
	// We expect that it won't get sent on.
	str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		<-done
		return []byte("bar"), nil
	})
	str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		<-testDone
		return nil, errors.New("test done")
	}).MaxTimes(1)
	closeStream := make(chan struct{})
	str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
		<-closeStream
		return 0, io.EOF
	})
	r, err := s.ParseRequest(req)
	require.NoError(t, err)
	go s.Proxy(&http3ResponseWriter{ResponseWriter: rec, str: str}, r)
	require.Equal(t, http.StatusOK, rec.Code)

	b := make([]byte, 100)
	n, _, err := remoteServerConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), b[:n])

	var once sync.Once
	str.EXPECT().Close().Do(func() error {
		once.Do(func() { close(done) })
		return nil
	}).MinTimes(1)
	close(closeStream)

	// Make sure that the "bar" datagram didn't get proxied.
	remoteServerConn.SetReadDeadline(time.Now().Add(scaleDuration(25 * time.Millisecond)))
	_, _, err = remoteServerConn.ReadFrom(b)
	require.Error(t, err)
}

func TestProxyDialFailure(t *testing.T) {
	s := Proxy{
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
	}
	r := newRequest("https://localhost:1234/masque?h=localhost&p=70000") // invalid port number
	req, err := s.ParseRequest(r)
	require.NoError(t, err)
	rec := httptest.NewRecorder()

	require.ErrorContains(t, s.Proxy(rec, req), "invalid port")
	require.Equal(t, http.StatusGatewayTimeout, rec.Code)
}

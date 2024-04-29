package masque_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
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

const requestProtocol = "connect-udp"

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
	mux := http.NewServeMux()
	s := masque.Server{
		Server:   http3.Server{Handler: mux},
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
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

func TestServerCloseProxiedConn(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	remoteServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	mux := http.NewServeMux()
	s := masque.Server{
		Server:   http3.Server{Handler: mux},
		Template: uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
	}
	req := newRequest(fmt.Sprintf("https://localhost:1234/masque?h=localhost&p=%d", remoteServerConn.LocalAddr().(*net.UDPAddr).Port))
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	str := NewMockStream(mockCtrl)
	str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		return []byte("foo"), nil
	})
	// This datagram is received after the connection is closed.
	// We expect that it won't get sent on.
	str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		<-done
		return []byte("bar"), nil
	})
	closeStream := make(chan struct{})
	str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
		<-closeStream
		return 0, io.EOF
	})
	require.NoError(t, s.Upgrade(&http3ResponseWriter{ResponseWriter: rec, str: str}, req))
	require.Equal(t, http.StatusOK, rec.Code)

	var once sync.Once
	str.EXPECT().Close().Do(func() error {
		once.Do(func() { close(done) })
		return nil
	}).AnyTimes()
	close(closeStream)

	b := make([]byte, 100)
	n, _, err := remoteServerConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), b[:n])
	// Make sure that the "bar" datagram didn't get proxied.
	remoteServerConn.SetReadDeadline(time.Now().Add(scaleDuration(25 * time.Millisecond)))
	_, _, err = remoteServerConn.ReadFrom(b)
	require.Error(t, err)
}

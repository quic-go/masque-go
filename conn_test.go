package masque_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/stretchr/testify/require"
)

func setupProxiedConn(t *testing.T) (*http3.Stream, net.PacketConn) {
	t.Helper()

	targetConn := newUDPConnLocalhost(t)

	strChan := make(chan *http3.Stream, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		strChan <- w.(http3.HTTPStreamer).HTTPStream()
	})
	server := http3.Server{
		TLSConfig:       tlsConf,
		Handler:         mux,
		EnableDatagrams: true,
	}
	t.Cleanup(func() { server.Close() })
	serverConn := newUDPConnLocalhost(t)
	go server.Serve(serverConn)

	cl := masque.Client{
		TLSClientConfig: &tls.Config{
			ClientCAs:          certPool,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: true,
		},
	}
	t.Cleanup(func() { cl.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, rsp, err := cl.Dial(
		ctx,
		uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", serverConn.LocalAddr().(*net.UDPAddr).Port)),
		targetConn.LocalAddr().(*net.UDPAddr),
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	t.Cleanup(func() { conn.Close() })

	var str *http3.Stream
	select {
	case str = <-strChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return str, conn
}

func TestCapsuleSkipping(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	str, conn := setupProxiedConn(t)

	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, 1337, []byte("foo")))
	require.NoError(t, http3.WriteCapsule(&buf, 42, []byte("bar")))
	_, err := str.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, str.Close())

	_, _, err = conn.ReadFrom(make([]byte, 100))
	require.ErrorIs(t, err, io.EOF)
}

func TestReadDeadline(t *testing.T) {
	t.Run("read after deadline", func(t *testing.T) {
		_, conn := setupProxiedConn(t)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
		_, _, err := conn.ReadFrom(make([]byte, 100))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("unblocking read", func(t *testing.T) {
		_, conn := setupProxiedConn(t)

		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		select {
		case err := <-errChan:
			t.Fatalf("didn't expect ReadFrom to return early: %v", err)
		case <-time.After(scaleDuration(50 * time.Millisecond)):
		}
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		case <-time.After(scaleDuration(100 * time.Millisecond)):
			t.Fatal("timeout")
		}
		_, _, err := conn.ReadFrom(make([]byte, 100))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("extending the deadline", func(t *testing.T) {
		_, conn := setupProxiedConn(t)

		start := time.Now()
		d := scaleDuration(75 * time.Millisecond)
		require.NoError(t, conn.SetReadDeadline(start.Add(d)))
		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		require.NoError(t, conn.SetReadDeadline(start.Add(2*d)))
		select {
		case err := <-errChan:
			if since := time.Since(start); since < 2*d {
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
				t.Fatalf("ReadFrom returned early: %s, expected >= %s", since, 2*d)
			}
		case <-time.After(10 * d):
			t.Fatal("timeout")
		}
	})

	t.Run("cancelling the deadline", func(t *testing.T) {
		_, conn := setupProxiedConn(t)

		start := time.Now()
		d := scaleDuration(75 * time.Millisecond)
		require.NoError(t, conn.SetReadDeadline(start.Add(d)))
		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		require.NoError(t, conn.SetReadDeadline(time.Time{}))
		select {
		case <-errChan:
			t.Fatal("deadline was cancelled")
		case <-time.After(2 * d):
		}

		// test shutdown
		require.NoError(t, conn.SetReadDeadline(time.Now()))
		select {
		case err := <-errChan:
			require.Error(t, err)
		case <-time.After(scaleDuration(100 * time.Millisecond)):
			t.Fatal("timeout")
		}
	})

	t.Run("multiple deadlines", func(t *testing.T) {
		_, conn := setupProxiedConn(t)

		const num = 10
		const maxDeadline = 5 * time.Millisecond

		for range num {
			// random duration between -5ms and 5ms
			d := scaleDuration(maxDeadline - time.Duration(rand.Int64N(2*maxDeadline.Nanoseconds())))
			t.Logf("setting deadline to %v", d)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(d)))
			_, _, err := conn.ReadFrom(make([]byte, 100))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		}
	})
}

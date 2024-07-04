package masque_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func runEchoServer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() {
		for {
			b := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	return conn
}

func TestProxyToIP(t *testing.T) {
	remoteServerConn := runEchoServer(t)
	defer remoteServerConn.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()
	t.Logf("server listening on %s", conn.LocalAddr())
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	defer server.Close()
	proxy := masque.Proxy{}
	defer proxy.Close()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseRequest(r, template)
		if err != nil {
			t.Log("Upgrade failed:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxy.Proxy(w, req)
	})
	go func() {
		if err := server.Serve(conn); err != nil {
			return
		}
	}()

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	defer cl.Close()
	proxiedConn, err := cl.Dial(context.Background(), remoteServerConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), remoteServerConn.LocalAddr())
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
}

func TestProxyToHostname(t *testing.T) {
	remoteServerConn := runEchoServer(t)
	defer remoteServerConn.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()
	t.Logf("server listening on %s", conn.LocalAddr())
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	defer server.Close()
	proxy := masque.Proxy{}
	defer proxy.Close()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseRequest(r, template)
		if err != nil {
			t.Log("Upgrade failed:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Target != "quic-go.net:1234" {
			t.Log("unexpected request target:", req.Target)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		// In this test, we don't actually want to connect to quic-go.net
		// Replace the target with the UDP echoer we spun up earlier.
		req.Target = remoteServerConn.LocalAddr().String()
		proxy.Proxy(w, req)
	})
	go func() {
		if err := server.Serve(conn); err != nil {
			return
		}
	}()

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	defer cl.Close()
	proxiedConn, err := cl.DialAddr(context.Background(), "quic-go.net:1234") // the proxy doesn't actually resolve this hostname
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), nil)
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
}

func TestProxyToHostnameMissingPort(t *testing.T) {
	cl := masque.Client{
		Template:        uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"),
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	defer cl.Close()
	_, err := cl.DialAddr(context.Background(), "quic-go.net") // missing port
	require.ErrorContains(t, err, "address quic-go.net: missing port in address")
}

func TestProxyShutdown(t *testing.T) {
	remoteServerConn := runEchoServer(t)
	defer remoteServerConn.Close()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer conn.Close()
	t.Logf("server listening on %s", conn.LocalAddr())
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	defer server.Close()
	proxy := masque.Proxy{}
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseRequest(r, template)
		if err != nil {
			t.Log("Upgrade failed:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxy.Proxy(w, req)
	})
	go func() {
		if err := server.Serve(conn); err != nil {
			return
		}
	}()

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	defer cl.Close()
	proxiedConn, err := cl.Dial(context.Background(), remoteServerConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), remoteServerConn.LocalAddr())
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])

	// Close the server and expect the proxied connection to unblock ReadFrom and WriteTo.
	proxy.Close()
	_, _, err = proxiedConn.ReadFrom(b)
	require.Error(t, err)
	var errored bool
	for i := 0; i < 10; i++ {
		if _, err := proxiedConn.WriteTo(b, remoteServerConn.LocalAddr()); err != nil {
			errored = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, errored, "expected datagram write side to error")
}

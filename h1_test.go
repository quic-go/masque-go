package masque_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestH1(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteServerConn := runEchoServer(t, addr)
	defer remoteServerConn.Close()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer listener.Close()

	template := uritemplate.MustNew(fmt.Sprintf("http://localhost:%d/masque?h={target_host}&p={target_port}", listener.Addr().(*net.TCPAddr).Port))

	proxy := masque.Proxy{}
	defer proxy.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			t.Log("Upgrade failed:", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err := proxy.Proxy(w, req); err != nil {
			t.Error(err)
		}
	})
	server := http.Server{Handler: mux}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	tr := masque.H1Transport{}
	req, err := masque.NewRequest(context.Background(), template, remoteServerConn.LocalAddr().String())
	require.NoError(t, err)

	proxiedConn, rsp, err := tr.Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
	defer proxiedConn.Close()

	_, err = proxiedConn.WriteTo([]byte("foobar"), remoteServerConn.LocalAddr())
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, raddr, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])

	expected := remoteServerConn.LocalAddr().(*net.UDPAddr)
	observed := raddr.(*net.UDPAddr)
	require.True(t, observed.IP.Equal(expected.IP))
	require.Equal(t, expected.Port, observed.Port)
}

func TestH1ClientConnWithPreDialedConnAndCustomHeaders(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteServerConn := runEchoServer(t, addr)
	defer remoteServerConn.Close()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer listener.Close()

	template := uritemplate.MustNew(fmt.Sprintf("http://localhost:%d/masque?h={target_host}&p={target_port}", listener.Addr().(*net.TCPAddr).Port))

	proxy := masque.Proxy{}
	defer proxy.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer my-secret-token", r.Header.Get("Authorization"))
		require.Equal(t, "connect-udp-custom", r.Header.Get("Upgrade"))

		// On server, normalize or handle
		req := &masque.ProxyRequest{
			Host:       r.Host,
			Target:     remoteServerConn.LocalAddr().String(),
			ProtoMajor: r.ProtoMajor,
		}

		udpConn, err := net.DialUDP("udp", nil, remoteServerConn.LocalAddr().(*net.UDPAddr))
		require.NoError(t, err)

		w.Header().Set("Upgrade", "connect-udp-custom")
		if err := proxy.ProxyConnectedSocket(w, req, udpConn); err != nil {
			t.Error(err)
		}
	})
	server := http.Server{Handler: mux}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	// Simulate an already-dialed connection from a custom dialer
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	clientConn := masque.NewH1ClientConn(rawConn)
	defer clientConn.Close()

	req, err := masque.NewRequest(context.Background(), template, remoteServerConn.LocalAddr().String())
	require.NoError(t, err)
	req.Header().Set("Authorization", "Bearer my-secret-token")
	req.Header().Set("Upgrade", "connect-udp-custom")

	proxiedConn, rsp, err := clientConn.Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
	require.Equal(t, "connect-udp-custom", rsp.Header.Get("Upgrade"))
	defer proxiedConn.Close()

	_, err = proxiedConn.WriteTo([]byte("test-payload"), nil)
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("test-payload"), buf[:n])
}

func TestH1CapsuleTransport(t *testing.T) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn1 := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)
	conn2 := masque.ProxiedPacketConn(nil, rspWriter, reqReader, nil, nil)

	input := []byte{1, 2, 3, 4, 5}
	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn1.WriteTo(input, addr)
		require.NoError(t, err)
	}()

	buf := make([]byte, 1024)
	n, _, err := conn2.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, input, buf[:n])

	conn1.Close()
	conn2.Close()
}

func TestProxyRequestProtocolCaseSensitivity(t *testing.T) {
	template := uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}")

	t.Run("HTTP/1.1 Upgrade is case-insensitive", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Method = http.MethodGet
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.Header.Set("Upgrade", "Connect-UDP")
		r, err := masque.ParseProxyRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)
	})

	t.Run("HTTP/3 :protocol is case-sensitive", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Proto = "Connect-UDP"
		_, err := masque.ParseProxyRequest(req, template)
		require.EqualError(t, err, "unexpected protocol: Connect-UDP")
		require.Equal(t, http.StatusNotImplemented, err.(*masque.ProxyRequestParseError).HTTPStatus)
	})
}

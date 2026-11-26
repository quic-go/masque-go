package masque_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

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

	require.NoError(t, proxiedConn.Close())
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

	_, err = proxiedConn.WriteTo([]byte("test-payload"), nil)
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("test-payload"), buf[:n])

	require.NoError(t, proxiedConn.Close())
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
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "Connect-UDP")
		r, err := masque.ParseProxyRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)
	})

	t.Run("HTTP/1.1 requires Connection: Upgrade token", func(t *testing.T) {
		newH1Req := func() *http.Request {
			req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
			req.Method = http.MethodGet
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.Header.Set("Upgrade", "connect-udp")
			return req
		}

		// Missing Connection header
		_, err := masque.ParseProxyRequest(newH1Req(), template)
		require.EqualError(t, err, "expected Connection: Upgrade header in HTTP/1.1")
		require.Equal(t, http.StatusBadRequest, err.(*masque.ProxyRequestParseError).HTTPStatus)

		// Connection header without Upgrade token
		req := newH1Req()
		req.Header.Set("Connection", "keep-alive, upgraded")
		_, err = masque.ParseProxyRequest(req, template)
		require.EqualError(t, err, "expected Connection: Upgrade header in HTTP/1.1")
		require.Equal(t, http.StatusBadRequest, err.(*masque.ProxyRequestParseError).HTTPStatus)

		// Comma-separated case-insensitive token
		req = newH1Req()
		req.Header.Set("Connection", "keep-alive, upgrade")
		r, err := masque.ParseProxyRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)

		// Multiple Connection header lines
		req = newH1Req()
		req.Header.Add("Connection", "keep-alive")
		req.Header.Add("Connection", "UPGRADE")
		r, err = masque.ParseProxyRequest(req, template)
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

	t.Run("HTTP/1.0 is rejected", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Method = http.MethodGet
		req.Proto = "HTTP/1.0"
		req.ProtoMajor = 1
		req.ProtoMinor = 0
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "connect-udp")
		_, err := masque.ParseProxyRequest(req, template)
		require.Equal(t, http.StatusHTTPVersionNotSupported, err.(*masque.ProxyRequestParseError).HTTPStatus)
	})

	t.Run("HTTP/1.1 multi-token Upgrade header", func(t *testing.T) {
		req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
		req.Method = http.MethodGet
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "h2c, connect-udp")
		r, err := masque.ParseProxyRequest(req, template)
		require.NoError(t, err)
		require.Equal(t, "localhost:1337", r.Target)
	})

	t.Run("forbidden Capsule Protocol headers", func(t *testing.T) {
		for _, hdr := range []struct {
			key, val string
		}{
			{"Content-Length", "0"},
			{"Content-Type", "text/plain"},
			{"Transfer-Encoding", "chunked"},
		} {
			req := newRequest("https://localhost:1234/masque?h=localhost&p=1337")
			req.Method = http.MethodGet
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "connect-udp")
			req.Header.Set(hdr.key, hdr.val)
			_, err := masque.ParseProxyRequest(req, template)
			require.Error(t, err, hdr.key)
			require.Equal(t, http.StatusBadRequest, err.(*masque.ProxyRequestParseError).HTTPStatus)
		}
	})
}

func TestH1ClientConnBufferedFirstCapsule(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	template := uritemplate.MustNew("http://localhost:8080/masque?h={target_host}&p={target_port}")

	go func() {
		defer serverRaw.Close()
		_, err := http.ReadRequest(bufio.NewReader(serverRaw))
		if err != nil {
			return
		}
		// Send the 101 response and the first DATAGRAM capsule in a single Write
		// so http.ReadResponse's bufio.Reader buffers the capsule bytes.
		respAndCapsule := append(
			[]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"),
			0x00, 6, 0x00, 'h', 'e', 'l', 'l', 'o',
		)
		_, _ = serverRaw.Write(respAndCapsule)
	}()

	clientConn := masque.NewH1ClientConn(clientRaw)
	defer clientConn.Close()

	req, err := masque.NewRequest(context.Background(), template, "127.0.0.1:1234")
	require.NoError(t, err)

	pconn, rsp, err := clientConn.Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
	defer pconn.Close()

	require.NoError(t, pconn.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 1500)
	n, _, err := pconn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), buf[:n])
}

func TestH1TransportDialContextCancellation(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer listener.Close()

	reqReceived := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		close(reqReceived)
		<-done
	}()

	template := uritemplate.MustNew(fmt.Sprintf("http://localhost:%d/masque?h={target_host}&p={target_port}", listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := masque.NewRequest(ctx, template, "127.0.0.1:1234")
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		tr := masque.H1Transport{}
		_, _, err := tr.Dial(req)
		errCh <- err
	}()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-reqReceived:
	case err := <-errCh:
		t.Fatalf("H1Transport.Dial failed before request was received: %v", err)
	case <-timer.C:
		t.Fatal("timed out waiting for server to receive request")
	}
	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-timer.C:
		t.Fatal("H1Transport.Dial did not return promptly after context cancellation")
	}
}

func TestH1TransportDialContextCancelAfterSuccess(t *testing.T) {
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
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = proxy.Proxy(w, req)
	})
	server := http.Server{Handler: mux}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	req, err := masque.NewRequest(ctx, template, remoteServerConn.LocalAddr().String())
	require.NoError(t, err)

	tr := masque.H1Transport{}
	pconn, rsp, err := tr.Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
	defer pconn.Close()

	// Cancelling the dial context after Dial returns must not affect the PacketConn.
	cancel()

	_, err = pconn.WriteTo([]byte("after-cancel"), remoteServerConn.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, _, err := pconn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("after-cancel"), buf[:n])
}

type hijackResponseWriter struct {
	header   http.Header
	conn     net.Conn
	rw       *bufio.ReadWriter
	hijacked bool
}

func newHijackResponseWriter(conn net.Conn, buffered []byte) *hijackResponseWriter {
	br := bufio.NewReader(bytes.NewReader(buffered))
	// Pre-fill bufio.Reader so br.Buffered() deterministically equals len(buffered).
	_, _ = br.Peek(1)
	return &hijackResponseWriter{
		header: make(http.Header),
		conn:   conn,
		rw:     bufio.NewReadWriter(br, bufio.NewWriter(conn)),
	}
}

func (h *hijackResponseWriter) Header() http.Header         { return h.header }
func (h *hijackResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (h *hijackResponseWriter) WriteHeader(int)             {}
func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return h.conn, h.rw, nil
}

func TestH1RejectsOptimisticDatagrams(t *testing.T) {
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer targetConn.Close()

	targetAddr := targetConn.LocalAddr().(*net.UDPAddr)
	template := uritemplate.MustNew("http://localhost:8080/masque?h={target_host}&p={target_port}")
	httpReq, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost:8080/masque?h=%s&p=%d", targetAddr.IP.String(), targetAddr.Port),
		nil,
	)
	require.NoError(t, err)
	httpReq.Header.Set("Connection", "Upgrade")
	httpReq.Header.Set("Upgrade", "connect-udp")
	httpReq.Header.Set("Capsule-Protocol", "?1")

	req, err := masque.ParseProxyRequest(httpReq, template)
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	optimisticCapsule := []byte{0x00, 10, 0x00, 'o', 'p', 't', 'i', 'm', 'i', 's', 't', '!'}
	w := newHijackResponseWriter(serverConn, optimisticCapsule)

	proxy := masque.Proxy{}
	defer proxy.Close()

	proxyErrCh := make(chan error, 1)
	go func() {
		proxyErrCh <- proxy.Proxy(w, req)
	}()

	rsp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	require.NoError(t, err)
	defer rsp.Body.Close()
	require.Equal(t, http.StatusBadRequest, rsp.StatusCode)
	require.Empty(t, rsp.Header.Get("Capsule-Protocol"))
	require.Contains(t, rsp.Header.Get("Proxy-Status"), "details=")
	require.Contains(t, rsp.Header.Get("Proxy-Status"), "optimistic data")

	select {
	case err := <-proxyErrCh:
		require.ErrorContains(t, err, "client sent optimistic data")
	case <-time.After(time.Second):
		t.Fatal("expected proxy.Proxy to return an error")
	}

	// Ensure the optimistic datagram was never forwarded to the UDP target.
	require.NoError(t, targetConn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	buf := make([]byte, 1500)
	_, _, err = targetConn.ReadFromUDP(buf)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())
}

func TestH1ClientConnRejectsInvalidUpgradeResponse(t *testing.T) {
	template := uritemplate.MustNew("http://localhost:8080/masque?h={target_host}&p={target_port}")

	tests := []struct {
		name       string
		reqUpgrade string
		rawResp    string
		wantErr    string
	}{
		{
			name:    "wrong Upgrade protocol",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			wantErr: "unexpected Upgrade header",
		},
		{
			name:    "missing Connection Upgrade",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: connect-udp\r\n\r\n",
			wantErr: "missing Connection: Upgrade",
		},
		{
			name:    "multiple Upgrade headers",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nUpgrade: websocket\r\n\r\n",
			wantErr: "unexpected Upgrade header",
		},
		{
			name:       "custom Upgrade mismatch",
			reqUpgrade: "connect-udp-custom",
			rawResp:    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n",
			wantErr:    "unexpected Upgrade header",
		},
		{
			name:    "forbidden Content-Length",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Length: 0\r\n\r\n",
			wantErr: "forbidden content/transfer header",
		},
		{
			name:    "forbidden Content-Type",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Type: text/plain\r\n\r\n",
			wantErr: "forbidden content/transfer header",
		},
		{
			name:    "forbidden Transfer-Encoding",
			rawResp: "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nTransfer-Encoding: chunked\r\n\r\n",
			wantErr: "forbidden content/transfer header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			defer serverRaw.Close()
			require.NoError(t, serverRaw.SetReadDeadline(time.Now().Add(time.Second)))

			go func() {
				_, err := http.ReadRequest(bufio.NewReader(serverRaw))
				if err != nil {
					return
				}
				_, _ = serverRaw.Write([]byte(tc.rawResp))
			}()

			clientConn := masque.NewH1ClientConn(clientRaw)
			defer clientConn.Close()

			req, err := masque.NewRequest(context.Background(), template, "127.0.0.1:1234")
			require.NoError(t, err)
			if tc.reqUpgrade != "" {
				req.Header().Set("Upgrade", tc.reqUpgrade)
			}

			pconn, rsp, err := clientConn.Dial(req)
			require.ErrorContains(t, err, tc.wantErr)
			require.Nil(t, pconn)
			require.NotNil(t, rsp)
			require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)

			// RFC 9298 Section 3.3: client MUST abort the connection on invalid 101 response.
			_, readErr := serverRaw.Read(make([]byte, 1))
			require.ErrorIs(t, readErr, io.EOF)
		})
	}
}

func TestH1RejectsOptimisticDatagramsWithoutProxyStatus(t *testing.T) {
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer targetConn.Close()

	udpConn, err := net.DialUDP("udp", nil, targetConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	optimisticCapsule := []byte{0x00, 10, 0x00, 'o', 'p', 't', 'i', 'm', 'i', 's', 't', '!'}
	w := newHijackResponseWriter(serverConn, optimisticCapsule)

	proxy := masque.Proxy{}
	defer proxy.Close()

	req := &masque.ProxyRequest{
		Host:       "localhost:8080",
		Target:     targetConn.LocalAddr().String(),
		ProtoMajor: 1,
	}

	proxyErrCh := make(chan error, 1)
	go func() {
		proxyErrCh <- proxy.ProxyConnectedSocket(w, req, udpConn)
	}()

	rsp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	require.NoError(t, err)
	defer rsp.Body.Close()
	require.Equal(t, http.StatusBadRequest, rsp.StatusCode)
	require.Empty(t, rsp.Header.Get("Capsule-Protocol"))

	select {
	case err := <-proxyErrCh:
		require.ErrorContains(t, err, "client sent optimistic data")
	case <-time.After(time.Second):
		t.Fatal("expected proxy.ProxyConnectedSocket to return an error")
	}
}

func TestH1ClientConnTrimmedUpgrade(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	template := uritemplate.MustNew("http://localhost:8080/masque?h={target_host}&p={target_port}")

	go func() {
		defer serverRaw.Close()
		_, err := http.ReadRequest(bufio.NewReader(serverRaw))
		if err != nil {
			return
		}
		_, _ = serverRaw.Write([]byte(
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp-custom\r\nCapsule-Protocol: ?1\r\n\r\n",
		))
	}()

	clientConn := masque.NewH1ClientConn(clientRaw)
	defer clientConn.Close()

	req, err := masque.NewRequest(context.Background(), template, "127.0.0.1:1234")
	require.NoError(t, err)
	req.Header().Set("Upgrade", " connect-udp-custom ")

	pconn, rsp, err := clientConn.Dial(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
	require.Equal(t, "connect-udp-custom", rsp.Header.Get("Upgrade"))
	require.NoError(t, pconn.Close())
}

func TestH1ProxyClose(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteServerConn := runEchoServer(t, addr)
	defer remoteServerConn.Close()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer listener.Close()

	template := uritemplate.MustNew(fmt.Sprintf("http://localhost:%d/masque?h={target_host}&p={target_port}", listener.Addr().(*net.TCPAddr).Port))
	proxy := masque.Proxy{}

	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = proxy.Proxy(w, req)
	})
	server := http.Server{Handler: mux}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	tr := masque.H1Transport{}
	req, err := masque.NewRequest(context.Background(), template, remoteServerConn.LocalAddr().String())
	require.NoError(t, err)

	pconn, _, err := tr.Dial(req)
	require.NoError(t, err)
	defer pconn.Close()

	require.NoError(t, proxy.Close())

	_, _, err = pconn.ReadFrom(make([]byte, 1500))
	require.Error(t, err)
}

func TestH1TLS(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteServerConn := runEchoServer(t, addr)
	defer remoteServerConn.Close()

	serverTLSConf := tlsConf.Clone()
	serverTLSConf.NextProtos = []string{"http/1.1"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConf)
	require.NoError(t, err)
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", port))

	proxy := masque.Proxy{}
	defer proxy.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Verify middleware-added Content-Type is stripped on 101 responses.
		w.Header().Set("Content-Type", "text/plain")
		if err := proxy.Proxy(w, req); err != nil {
			t.Error(err)
		}
	})
	server := http.Server{
		Handler:      mux,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	defer server.Close()
	go func() {
		_ = server.Serve(listener)
	}()

	t.Run("with RootCAs and empty ServerName/NextProtos", func(t *testing.T) {
		tr := masque.H1Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		}
		req, err := masque.NewRequest(context.Background(), template, remoteServerConn.LocalAddr().String())
		require.NoError(t, err)

		pconn, rsp, err := tr.Dial(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusSwitchingProtocols, rsp.StatusCode)
		require.Empty(t, rsp.Header.Get("Content-Type"))

		_, err = pconn.WriteTo([]byte("tls-hello"), remoteServerConn.LocalAddr())
		require.NoError(t, err)
		buf := make([]byte, 1500)
		n, _, err := pconn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, []byte("tls-hello"), buf[:n])
		require.NoError(t, pconn.Close())
	})

	t.Run("nil TLSClientConfig sets ServerName", func(t *testing.T) {
		tr := masque.H1Transport{}
		req, err := masque.NewRequest(context.Background(), template, remoteServerConn.LocalAddr().String())
		require.NoError(t, err)

		// Fails certificate verification (self-signed test CA), NOT missing ServerName.
		_, _, err = tr.Dial(req)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "ServerName")
	})
}

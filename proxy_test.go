package masque_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
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
	req.Proto = "connect-udp"
	req.Header.Add("Capsule-Protocol", "?1")
	return req
}

func TestProxyCloseProxiedConn(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	serverPort := serverConn.LocalAddr().(*net.UDPAddr).Port
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", serverPort))

	p := masque.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseRequest(r, template)
		if err != nil {
			t.Logf("error parsing request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		p.Proxy(w, req)
	})
	server := &http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}
	defer server.Close()
	go server.ServeQUICConn(serverConn)

	tr := &http3.Transport{
		EnableDatagrams: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reqStr, err := tr.NewClientConn(clientConn).OpenRequestStream(ctx)
	require.NoError(t, err)

	targetConn := newUDPConnLocalhost(t)
	req := newRequest(fmt.Sprintf("https://localhost:%d/masque?h=localhost&p=%d", serverPort, targetConn.LocalAddr().(*net.UDPAddr).Port))
	require.NoError(t, reqStr.SendRequestHeader(req))
	hdr, err := reqStr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, hdr.StatusCode)

	// Check proxy-status header
	proxyStatus := hdr.Header.Get("Proxy-Status")
	hostPart := fmt.Sprintf(`"localhost:%d";`, serverPort)
	require.Equal(t, hostPart, proxyStatus[:len(hostPart)])
	nextHop := fmt.Sprintf(`;next-hop="%s"`, targetConn.LocalAddr().String())
	require.Contains(t, proxyStatus, nextHop)

	// we don't use reqStr.SendDatagram(), because we want to be able to send datagrams for this stream after we've closed it
	sendDatagram := func(t *testing.T, b []byte) {
		t.Helper()
		data := quicvarint.Append(nil, uint64(reqStr.StreamID()/4)) // quarter stream ID
		data = append(data, byte(0))                                // context ID
		require.NoError(t, clientConn.SendDatagram(append(data, b...)))
	}

	sendDatagram(t, []byte("foo"))

	b := make([]byte, 100)
	targetConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := targetConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), b[:n])
	require.NoError(t, reqStr.Close())

	// make sure the stream is recognized as closed by the proxy
	time.Sleep(scaleDuration(20 * time.Millisecond))

	sendDatagram(t, []byte("bar"))

	// make sure that the "bar" datagram didn't get proxied
	targetConn.SetReadDeadline(time.Now().Add(scaleDuration(25 * time.Millisecond)))
	_, _, err = targetConn.ReadFrom(b)
	require.Error(t, err)
}

func TestProxyBadPort(t *testing.T) {
	p := masque.Proxy{}
	r := newRequest("https://localhost:1234/masque?h=localhost&p=70000") // invalid port number
	req, err := masque.ParseRequest(r, uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"))
	require.NoError(t, err)
	rec := httptest.NewRecorder()

	require.ErrorContains(t, p.Proxy(rec, req), "invalid port")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	proxyStatus := rec.Header().Get("Proxy-Status")
	hostPart := `"localhost:1234";`
	require.Equal(t, hostPart, proxyStatus[:len(hostPart)])
	require.Contains(t, proxyStatus, ";details=")
	require.Contains(t, proxyStatus, "invalid port")
	require.NotContains(t, proxyStatus, ";error=")
}

func TestProxyNXDOMAIN(t *testing.T) {
	p := masque.Proxy{}
	r := newRequest("https://localhost:1234/masque?h=nxdomain.test&p=12345") // invalid port number
	req, err := masque.ParseRequest(r, uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"))
	require.NoError(t, err)
	rec := httptest.NewRecorder()

	require.ErrorContains(t, p.Proxy(rec, req), "no such host")
	require.Equal(t, http.StatusBadGateway, rec.Code)

	proxyStatus := rec.Header().Get("Proxy-Status")
	hostPart := `"localhost:1234";`
	require.Equal(t, hostPart, proxyStatus[:len(hostPart)])
	require.Contains(t, proxyStatus, `;error="dns_error"`)
	require.Contains(t, proxyStatus, `;rcode="Negative response"`)
	require.Contains(t, proxyStatus, "details=")
	require.Contains(t, proxyStatus, "no such host")
}

func TestProxyingAfterClose(t *testing.T) {
	p := masque.Proxy{}
	require.NoError(t, p.Close())

	r := newRequest("https://localhost:1234/masque?h=localhost&p=1234")
	req, err := masque.ParseRequest(r, uritemplate.MustNew("https://localhost:1234/masque?h={target_host}&p={target_port}"))
	require.NoError(t, err)

	t.Run("proxying", func(t *testing.T) {
		rec := httptest.NewRecorder()
		require.ErrorIs(t, p.Proxy(rec, req), net.ErrClosed)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("proxying connected socket", func(t *testing.T) {
		rec := httptest.NewRecorder()
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		require.ErrorIs(t, p.ProxyConnectedSocket(rec, req, conn), net.ErrClosed)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}

package masque_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestTransportAddsDefaultPort(t *testing.T) {
	req, err := masque.NewRequest(t.Context(), uritemplate.MustNew("https://proxy.example/masque?h={target_host}&p={target_port}"), "target.example:443")
	require.NoError(t, err)

	dialErr := errors.New("dial stopped")
	tr := masque.Transport{
		DialAddr: func(_ context.Context, addr string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			require.Equal(t, "proxy.example:443", addr)
			return nil, dialErr
		},
	}
	_, _, err = tr.Dial(req)
	require.ErrorIs(t, err, dialErr)
}

func TestNewClientConnRequiresQUICDatagrams(t *testing.T) {
	conn, _ := newConnPairWithDatagrams(t, false)

	_, err := new(masque.Transport).NewClientConn(conn)
	require.ErrorContains(t, err, "Datagram support")
}

func TestNewClientConnSharesHTTP3Connection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientConn, serverConn := newConnPair(t)
	url := "https://" + serverConn.LocalAddr().String()
	template := uritemplate.MustNew(url + "/masque?h={target_host}&p={target_port}")
	targetConn := runEchoServer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer targetConn.Close()

	proxy := &masque.Proxy{}
	defer proxy.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			t.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := proxy.Proxy(w, req); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /hello", func(http.ResponseWriter, *http.Request) {})
	server := &http3.Server{Handler: mux, EnableDatagrams: true}
	defer server.Close()
	go server.ServeQUICConn(serverConn)

	h3conn := (&http3.Transport{EnableDatagrams: true}).NewClientConn(clientConn)
	httpClient := &http.Client{Transport: h3conn, Timeout: time.Second}
	checkHTTP := func() {
		t.Helper()
		rsp, err := httpClient.Get(url + "/hello")
		require.NoError(t, err)
		rsp.Body.Close()
		require.Equal(t, http.StatusOK, rsp.StatusCode)
	}

	checkHTTP()
	req, err := masque.NewRequest(ctx, template, targetConn.LocalAddr().String())
	require.NoError(t, err)
	tunnel, rsp, err := masque.NewClientConn(h3conn).Dial(req)
	require.NoError(t, err)
	defer tunnel.Close()
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	require.Equal(t, clientConn.LocalAddr().String(), tunnel.LocalAddr().String())
	require.Equal(t, "connect-udp", tunnel.LocalAddr().Network())
	checkHTTP()

	require.NoError(t, tunnel.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = tunnel.WriteTo([]byte("foobar"), nil)
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, addr, err := tunnel.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
	require.Equal(t, targetConn.LocalAddr().String(), addr.String())

	require.NoError(t, tunnel.Close())
	checkHTTP()
}

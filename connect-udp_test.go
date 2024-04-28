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
)

func TestProxy(t *testing.T) {
	remoteServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() {
		for {
			b := make([]byte, 1500)
			n, addr, err := remoteServerConn.ReadFrom(b)
			if err != nil {
				return
			}
			if _, err := remoteServerConn.WriteTo(b[:n], addr); err != nil {
				return
			}
		}
	}()
	defer remoteServerConn.Close()

	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	t.Logf("server listening on %s", conn.LocalAddr())
	template, err := uritemplate.New(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))
	require.NoError(t, err)

	mux := http.NewServeMux()
	server := masque.Server{
		Server: http3.Server{
			TLSConfig:       tlsConf,
			QUICConfig:      &quic.Config{EnableDatagrams: true},
			EnableDatagrams: true,
			Handler:         mux,
		},
		Template: template,
		Allow:    func(context.Context, *net.UDPAddr) bool { return true },
	}
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		if err := server.Upgrade(w, r); err != nil {
			t.Log("Upgrade failed:", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		if err := server.Serve(conn); err != nil {
			panic(err)
		}
	}()

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxiedConn, err := cl.DialIP(ctx, remoteServerConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), remoteServerConn.LocalAddr())
	require.NoError(t, err)

	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
}

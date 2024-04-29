package masque_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestProxy(t *testing.T) {
	remoteServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer remoteServerConn.Close()
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

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Logf("proxy listening on %s", conn.LocalAddr())
	template := uritemplate.MustNew(fmt.Sprintf("https://127.0.0.1:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))

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
	go server.Serve(conn)

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	proxiedConn, err := cl.DialIP(context.Background(), remoteServerConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), remoteServerConn.LocalAddr())
	require.NoError(t, err)

	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b[:n])
}

func TestCloseByClient(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Logf("proxy listening on %s", conn.LocalAddr())

	remoteServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer remoteServerConn.Close()
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

	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", conn.LocalAddr().(*net.UDPAddr).Port))
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
	go server.Serve(conn)

	cl := masque.Client{
		Template:        template,
		TLSClientConfig: &tls.Config{ClientCAs: certPool, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true},
	}
	proxiedConn, err := cl.DialIP(context.Background(), remoteServerConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)

	_, err = proxiedConn.WriteTo([]byte("foobar"), nil)
	require.NoError(t, err)
	b := make([]byte, 1500)
	n, _, err := proxiedConn.ReadFrom(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("foobar"), b[:n])
	proxiedConn.Close()
}

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
		err := server.Upgrade(w, r)
		fmt.Println("upgrade:", err)
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
	proxied, err := cl.DialIP(ctx, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	_ = proxied
}

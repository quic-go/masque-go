package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var proxyURITemplate string
	var keyFile, certFile string
	var insecureSkipVerify bool
	flag.StringVar(&proxyURITemplate, "t", "", "URI template")
	flag.StringVar(&keyFile, "k", "", "key file")
	flag.StringVar(&certFile, "c", "", "cert file")
	flag.BoolVar(&insecureSkipVerify, "i", false, "insecure skip verify")
	flag.Parse()
	if proxyURITemplate == "" || keyFile == "" || certFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 1. Create HTTP/3 server
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, world!"))
	})

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load certificate: %v", err)
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	server := http3.Server{
		Handler:         mux,
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		Logger:          slog.Default(),
	}
	defer server.Close()

	// 2. Let is listen via MASQUE proxy
	cl := masque.Client{
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: insecureSkipVerify,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	defer cl.Close()

	proxiedConn, publicAddrs, rsp, err := cl.Listen(context.Background(), uritemplate.MustNew(proxyURITemplate))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	if rsp.StatusCode != http.StatusOK {
		log.Fatalf("failed to listen: %s", rsp.Status)
	}

	// 3. Profit
	log.Printf("listening on %s", publicAddrs[0])
	server.Serve(proxiedConn)
}

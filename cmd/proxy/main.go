package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var templateStr, bind, keyFile, certFile string
	flag.StringVar(&templateStr, "t", "", "URI template")
	flag.StringVar(&bind, "b", "", "bind to (ip:port)")
	flag.StringVar(&keyFile, "k", "", "key file")
	flag.StringVar(&certFile, "c", "", "cert file")
	flag.Parse()

	if templateStr == "" || bind == "" || keyFile == "" || certFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	template, err := uritemplate.New(templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load certificate: %v", err)
	}
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	server := http3.Server{
		Addr:            bind,
		TLSConfig:       tlsConf,
		EnableDatagrams: true,
		Logger:          slog.Default(),
	}
	defer server.Close()
	proxy := masque.Proxy{}
	// parse the template to extract the path for the HTTP handler
	u, err := url.Parse(templateStr)
	if err != nil {
		log.Fatalf("failed to parse URI template: %v", err)
	}
	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseConnectUDPRequest(r, template)
		if err != nil {
			var perr *masque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proxy.Proxy(w, req)
	})
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to run proxy: %v", err)
	}
}

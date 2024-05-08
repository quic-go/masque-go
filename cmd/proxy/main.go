package main

import (
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var templateStr, bind, keyFile, certFile string
	flag.StringVar(&templateStr, "t", "", "URI template, must use a /masque endpoint")
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
	proxy := masque.Server{
		Template: template,
		Server: http3.Server{
			Addr:            bind,
			TLSConfig:       tlsConf,
			EnableDatagrams: true,
			Logger:          slog.Default(),
		},
	}
	http.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.Upgrade(w, r); err != nil {
			log.Printf("failed to upgrade request from %s: %v", r.RemoteAddr, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if err := proxy.ListenAndServe(); err != nil {
		log.Fatalf("failed to run proxy: %v", err)
	}
}

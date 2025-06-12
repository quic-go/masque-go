package main

import (
	"crypto/tls"
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

	if templateStr == "" || bind == "" {
		flag.Usage()
		os.Exit(1)
	}

	template, err := uritemplate.New(templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}
	proxy := masque.Proxy{Template: template, EnableDatagrams: true}
	// parse the template to extract the path for the HTTP handler
	u, err := url.Parse(templateStr)
	if err != nil {
		log.Fatalf("failed to parse URI template: %v", err)
	}
	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.Proxy(w, r); err != nil {
			log.Printf("failed to proxy: %v", err)
		}
	})

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to load certificate: %v", err)
		}
		go func() {
			h3tlsConf := http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			})
			h3server := http3.Server{
				Addr:            bind,
				TLSConfig:       h3tlsConf,
				EnableDatagrams: true,
				Logger:          slog.Default(),
			}
			if err := h3server.ListenAndServe(); err != nil {
				log.Fatalf("failed to run proxy in h3: %v", err)
			}
			h3server.Close()
		}()
	} else {
		log.Println("no certificate provided")
	}
}

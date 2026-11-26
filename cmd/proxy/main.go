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
	"time"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
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
	if (certFile == "") != (keyFile == "") {
		flag.Usage()
		os.Exit(1)
	}

	template, err := uritemplate.New(templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}
	proxy := masque.Proxy{}
	// parse the template to extract the path for the HTTP handler
	u, err := url.Parse(templateStr)
	if err != nil {
		log.Fatalf("failed to parse URI template: %v", err)
	}
	http.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			if perr, ok := errors.AsType[*masque.ProxyRequestParseError](err); ok {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err = proxy.Proxy(w, req); err != nil {
			log.Println(err)
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
				QUICConfig: &quic.Config{
					EnableDatagrams: true,
					// The default initial packet size is 1280, resulting in an inner
					// MTU estimate that is initially too small for some QUIC ServerInitials.
					InitialPacketSize: 1500, // Clamped to 1452 in quic-go/config.go.
				},
				Logger: slog.Default(),
			}
			if err := h3server.ListenAndServe(); err != nil {
				log.Fatalf("failed to run proxy in h3: %v", err)
			}
		}()
	} else {
		log.Println("no certificate provided, disabling HTTP/3")
	}

	h1server := http.Server{
		Addr:              bind,
		ReadHeaderTimeout: 10 * time.Second,
		// Disable HTTP/2 so TLS clients negotiate HTTP/1.1.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if len(certFile) > 0 {
		if err := h1server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("failed to run encrypted proxy in HTTP/1.1: %v", err)
		}
	} else {
		if err := h1server.ListenAndServe(); err != nil {
			log.Fatalf("failed to run plaintext proxy in HTTP/1.1: %v", err)
		}
	}
}

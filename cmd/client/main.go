package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/quic-go/masque-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	var proxyURITemplate string
	flag.StringVar(&proxyURITemplate, "t", "", "URI template.")
	var useQuic bool
	flag.BoolVar(&useQuic, "quic", true, "Use QUIC to reach the proxy.")
	var useDatagrams bool
	flag.BoolVar(&useDatagrams, "datagrams", true, "Use QUIC datagrams to reach the proxy.")
	var insecureTLS bool
	flag.BoolVar(&insecureTLS, "insecure-tls", false, "Ignore TLS certificate errors from the proxy.")
	flag.Parse()
	if proxyURITemplate == "" {
		flag.Usage()
		os.Exit(1)
	}

	parsedTemplate, err := uritemplate.New(proxyURITemplate)
	if err != nil {
		log.Fatalf("failed to parse template: %v", err)
	}

	urls := flag.Args()
	if len(urls) != 1 {
		log.Fatalf("Must specify exactly one destination URL (not %d)", len(urls))
	}

	var dialMasque func(req *masque.Request) (net.PacketConn, *http.Response, error)
	if useQuic {
		tr := &masque.Transport{
			QUICConfig: &quic.Config{
				EnableDatagrams:   useDatagrams,
				InitialPacketSize: 1350,
			},
			TLSClientConfig: &tls.Config{
				NextProtos:         []string{http3.NextProtoH3},
				InsecureSkipVerify: insecureTLS,
			},
		}
		dialMasque = func(req *masque.Request) (net.PacketConn, *http.Response, error) {
			return tr.Dial(req)
		}
	} else {
		// TODO: H2 Support (blocked on https://github.com/golang/go/issues/53208)
		tr := &masque.H1Transport{
			TLSClientConfig: &tls.Config{
				NextProtos:         []string{"http/1.1"},
				InsecureSkipVerify: insecureTLS,
			},
		}
		dialMasque = tr.Dial
	}

	host, port, err := extractHostAndPort(urls[0])
	if err != nil {
		log.Fatalf("failed to parse url: %v", err)
	}

	hcl := &http.Client{
		Transport: &http3.Transport{
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				raddr, err := net.ResolveUDPAddr("udp", host+":"+strconv.Itoa(int(port)))
				if err != nil {
					return nil, err
				}
				req, err := masque.NewRequest(ctx, parsedTemplate, raddr.String())
				if err != nil {
					return nil, err
				}
				pconn, _, err := dialMasque(req)
				if err != nil {
					log.Fatal("dialing MASQUE failed:", err)
				}
				log.Printf("dialed connection: %s <-> %s", pconn.LocalAddr(), raddr)
				quicConf = quicConf.Clone()
				quicConf.DisablePathMTUDiscovery = true
				return quic.DialEarly(ctx, pconn, raddr, tlsConf, quicConf)
			},
		},
	}
	rsp, err := hcl.Get(urls[0])
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	log.Printf("HTTP status: %d", rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		log.Fatalf("reading response body failed: %v", err)
	}
	log.Println(string(data))
}

func extractHostAndPort(template string) (string, uint16, error) {
	u, err := url.Parse(template)
	if err != nil {
		return "", 0, err
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil || portStr == "" {
		return u.Host, 443, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse port: %w", err)
	}
	return host, uint16(port), nil
}

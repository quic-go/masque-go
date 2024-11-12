package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
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
	flag.StringVar(&proxyURITemplate, "t", "", "URI template")
	flag.Parse()
	if proxyURITemplate == "" {
		flag.Usage()
		os.Exit(1)
	}
	urls := flag.Args()
	if len(urls) != 1 {
		slog.Error("usage: client -t <template> <url>")
		os.Exit(1)
	}

	cl := masque.Client{
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	host, port, err := extractHostAndPort(urls[0])
	if err != nil {
		slog.Error("failed to parse url", "err", err)
		os.Exit(1)
	}

	hcl := &http.Client{
		Transport: &http3.Transport{
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				raddr, err := net.ResolveUDPAddr("udp", host+":"+strconv.Itoa(int(port)))
				if err != nil {
					return nil, err
				}
				pconn, _, err := cl.Dial(context.Background(), uritemplate.MustNew(proxyURITemplate), raddr)
				if err != nil {
					slog.Error("dialing MASQUE failed", "err", err)
					os.Exit(1)
				}
				slog.Info(fmt.Sprintf("dialed connection: %s <-> %s", pconn.LocalAddr(), raddr))

				quicConf = quicConf.Clone()
				quicConf.DisablePathMTUDiscovery = true
				return quic.DialEarly(ctx, pconn, raddr, tlsConf, quicConf)
			},
		},
	}
	rsp, err := hcl.Get(urls[0])
	if err != nil {
		slog.Error("request failed", "err", err)
		os.Exit(1)
	}
	slog.Info("HTTP status", "status", rsp.StatusCode)
	data, err := io.ReadAll(rsp.Body)
	if err != nil {
		slog.Error("reading response body failed", "err", err)
		os.Exit(1)
	}
	slog.Info(string(data))
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

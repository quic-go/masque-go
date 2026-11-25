package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
)

// An H1ClientConn represents an HTTP/1.1 connection to a single proxy server.
// It is used when an established connection (e.g. from custom dialing or a TLS
// tunnel) is already available.
type H1ClientConn struct {
	conn net.Conn
}

// NewH1ClientConn creates a client connection using an existing network connection.
func NewH1ClientConn(conn net.Conn) *H1ClientConn {
	return &H1ClientConn{conn: conn}
}

// Dial dials a proxied UDP connection over the existing HTTP/1.1 connection.
// Custom headers (such as Authorization or Upgrade overrides) can be set directly on req.Header().
func (c *H1ClientConn) Dial(req *Request) (net.PacketConn, *http.Response, error) {
	httpReq := req.req
	if httpReq == nil || httpReq.URL == nil {
		return nil, nil, errors.New("masque: request URL is nil")
	}

	h1Req := httpReq.Clone(httpReq.Context())
	h1Req.Method = http.MethodGet
	if h1Req.Header == nil {
		h1Req.Header = make(http.Header)
	}
	h1Req.Header.Set("Connection", "Upgrade")
	if h1Req.Header.Get("Upgrade") == "" {
		h1Req.Header.Set("Upgrade", requestProtocol)
	}
	h1Req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)

	if err := h1Req.Write(c.conn); err != nil {
		return nil, nil, fmt.Errorf("masque: failed to write HTTP/1.1 request: %w", err)
	}

	rsp, err := http.ReadResponse(bufio.NewReader(c.conn), h1Req)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to read HTTP/1.1 response: %w", err)
	}

	if rsp.StatusCode != http.StatusSwitchingProtocols {
		return nil, rsp, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}

	laddr := masqueAddr{c.conn.LocalAddr().String()}
	return ProxiedPacketConn(nil, c.conn, c.conn, laddr, remoteAddr(rsp, req.target)), rsp, nil
}

func (c *H1ClientConn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// An H1Transport establishes proxied connections to remote hosts using HTTP/1.1,
// dialing a new connection for each proxy request.
type H1Transport struct {
	TLSClientConfig *tls.Config
	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil, net.Dialer is used.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTLSContext specifies an optional dial function for creating TLS connections.
	// If DialTLSContext is nil, DialContext and TLSClientConfig are used.
	DialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (t *H1Transport) dial(ctx context.Context, u *url.URL) (net.Conn, error) {
	authority := u.Host
	dialer := t.DialContext
	if dialer == nil {
		dialer = (&net.Dialer{}).DialContext
	}

	switch u.Scheme {
	case "http":
		if u.Port() == "" {
			authority = authority + ":80"
		}
		return dialer(ctx, "tcp", authority)
	case "https":
		if u.Port() == "" {
			authority = authority + ":443"
		}
		if t.DialTLSContext != nil {
			return t.DialTLSContext(ctx, "tcp", authority)
		}
		rawConn, err := dialer(ctx, "tcp", authority)
		if err != nil {
			return nil, err
		}
		tlsConf := t.TLSClientConfig
		if tlsConf == nil {
			tlsConf = &tls.Config{}
		}
		if tlsConf.ServerName == "" {
			c := tlsConf.Clone()
			c.ServerName = u.Hostname()
			tlsConf = c
		}
		tlsClient := tls.Client(rawConn, tlsConf)
		if err := tlsClient.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return tlsClient, nil
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

// Dial dials an HTTP/1.1 connection to the proxy and establishes a proxied UDP connection.
func (t *H1Transport) Dial(req *Request) (net.PacketConn, *http.Response, error) {
	if req.req == nil || req.req.URL == nil {
		return nil, nil, errors.New("masque: request URL is nil")
	}
	conn, err := t.dial(req.req.Context(), req.req.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: dialing HTTP/1.1 connection failed: %w", err)
	}
	clientConn := NewH1ClientConn(conn)
	pconn, rsp, err := clientConn.Dial(req)
	if err != nil {
		conn.Close()
		return nil, rsp, err
	}
	return pconn, rsp, nil
}

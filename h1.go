package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type sharedCloser struct {
	once sync.Once
	err  error
	c    io.Closer
}

func (s *sharedCloser) Close() error {
	s.once.Do(func() {
		s.err = s.c.Close()
	})
	return s.err
}

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
	if c == nil || c.conn == nil {
		return nil, nil, errors.New("masque: connection is nil")
	}
	if req == nil || req.req == nil || req.req.URL == nil {
		return nil, nil, errors.New("masque: request URL is nil")
	}
	httpReq := req.req

	ctx := httpReq.Context()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	if d, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(d); err != nil {
			return nil, nil, fmt.Errorf("masque: failed to set connection deadline: %w", err)
		}
	}

	stop := context.AfterFunc(ctx, func() {
		_ = c.conn.SetDeadline(time.Now())
	})
	defer stop()

	h1Req := httpReq.Clone(ctx)
	h1Req.Method = http.MethodGet
	if h1Req.Header == nil {
		h1Req.Header = make(http.Header)
	}
	h1Req.Header.Set("Connection", "Upgrade")
	upgradeProto := strings.Trim(h1Req.Header.Get("Upgrade"), " \t")
	// Allow users to override the upgrade header in case they are experimenting with different
	// proxy implementations.
	if upgradeProto == "" {
		upgradeProto = requestProtocol
		h1Req.Header.Set("Upgrade", upgradeProto)
	}
	h1Req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)

	if err := h1Req.Write(c.conn); err != nil {
		stop()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("masque: failed to write HTTP/1.1 request: %w", ctxErr)
		}
		return nil, nil, fmt.Errorf("masque: failed to write HTTP/1.1 request: %w", err)
	}

	br := bufio.NewReader(c.conn)
	rsp, err := http.ReadResponse(br, h1Req)
	if err != nil {
		stop()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("masque: failed to read HTTP/1.1 response: %w", ctxErr)
		}
		return nil, nil, fmt.Errorf("masque: failed to read HTTP/1.1 response: %w", err)
	}

	if !stop() {
		return nil, nil, ctx.Err()
	}
	_ = c.conn.SetDeadline(time.Time{})

	if rsp.StatusCode != http.StatusSwitchingProtocols {
		return nil, rsp, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}
	if !hasHeaderToken(rsp.Header, "Connection", "Upgrade") {
		_ = c.conn.Close()
		return nil, rsp, errors.New("masque: server response missing Connection: Upgrade header")
	}
	upgradeVals := rsp.Header.Values("Upgrade")
	if len(upgradeVals) != 1 || !strings.EqualFold(strings.TrimSpace(upgradeVals[0]), upgradeProto) {
		_ = c.conn.Close()
		return nil, rsp, fmt.Errorf("masque: unexpected Upgrade header in response: %v", upgradeVals)
	}
	if len(rsp.Header.Values("Content-Type")) > 0 ||
		len(rsp.Header.Values("Content-Length")) > 0 || rsp.ContentLength > 0 ||
		len(rsp.TransferEncoding) > 0 || len(rsp.Header.Values("Transfer-Encoding")) > 0 {
		_ = c.conn.Close()
		return nil, rsp, errors.New("masque: server 101 response contains forbidden content/transfer header")
	}

	laddr := masqueAddr{c.conn.LocalAddr().String()}
	closer := &sharedCloser{c: c.conn}
	reqWriter := struct {
		io.Writer
		io.Closer
	}{c.conn, closer}
	rspReader := struct {
		*bufio.Reader
		io.Closer
	}{br, closer}
	return ProxiedPacketConn(nil, reqWriter, rspReader, laddr, remoteAddr(rsp, req.target)), rsp, nil
}

// Close closes the underlying HTTP/1.1 connection.
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
			authority = net.JoinHostPort(u.Hostname(), "80")
		}
		return dialer(ctx, "tcp", authority)
	case "https":
		if u.Port() == "" {
			authority = net.JoinHostPort(u.Hostname(), "443")
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
			tlsConf = &tls.Config{
				ServerName: u.Hostname(),
				NextProtos: []string{"http/1.1"},
			}
		} else {
			c := tlsConf.Clone()
			if c.ServerName == "" {
				c.ServerName = u.Hostname()
			}
			c.NextProtos = []string{"http/1.1"}
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
	if req == nil || req.req == nil || req.req.URL == nil || req.req.URL.Host == "" {
		return nil, nil, errors.New("masque: request URL needs a host")
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

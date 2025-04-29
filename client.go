package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// defaultInitialPacketSize is an increased packet size used for the connection to the proxy.
// This allows tunneling QUIC connections, which themselves have a minimum MTU requirement of 1200 bytes.
const defaultInitialPacketSize = 1350

// A Client establishes proxied connections to remote hosts, using a UDP proxy.
// Multiple flows can be proxied via the same connection to the proxy.
type Client struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the "h3" ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config
	// Headers can be set to specify additional HTTP headers in the Extended CONNECT
	Headers http.Header

	dialOnce   sync.Once
	dialErr    error
	conn       quic.Connection
	clientConn *http3.ClientConn
}

// DialAddr dials a proxied connection to a target server.
// The target address is sent to the proxy, and the DNS resolution is left to the proxy.
// The target must be given as a host:port.
func (c *Client) DialAddr(ctx context.Context, proxyTemplate *uritemplate.Template, target string) (net.PacketConn, *http.Response, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse target: %w", err)
	}
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(host),
		uriTemplateTargetPort: uritemplate.String(port),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	return c.dial(ctx, str)
}

// Dial dials a proxied connection to a target server.
func (c *Client) Dial(ctx context.Context, proxyTemplate *uritemplate.Template, raddr *net.UDPAddr) (net.PacketConn, *http.Response, error) {
	str, err := proxyTemplate.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(escape(raddr.IP.String())),
		uriTemplateTargetPort: uritemplate.String(strconv.Itoa(raddr.Port)),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	return c.dial(ctx, str)
}

func (c *Client) dial(ctx context.Context, expandedTemplate string) (net.PacketConn, *http.Response, error) {
	u, err := url.Parse(expandedTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to parse URI: %w", err)
	}

	c.dialOnce.Do(func() {
		quicConf := c.QUICConfig
		if quicConf == nil {
			quicConf = &quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: defaultInitialPacketSize,
			}
		}
		if !quicConf.EnableDatagrams {
			c.dialErr = errors.New("masque: QUICConfig needs to enable Datagrams")
			return
		}
		tlsConf := c.TLSClientConfig
		if tlsConf == nil {
			tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
		}
		conn, err := quic.DialAddr(ctx, u.Host, tlsConf, quicConf)
		if err != nil {
			c.dialErr = fmt.Errorf("masque: dialing QUIC connection failed: %w", err)
			return
		}
		c.conn = conn
		tr := &http3.Transport{EnableDatagrams: true}
		c.clientConn = tr.NewClientConn(conn)
	})
	if c.dialErr != nil {
		return nil, nil, c.dialErr
	}
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-c.clientConn.Context().Done():
		return nil, nil, context.Cause(c.clientConn.Context())
	case <-c.clientConn.ReceivedSettings():
	}
	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("masque: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("masque: server didn't enable Datagrams")
	}

	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to open request stream: %w", err)
	}

	if c.Headers == nil {
		c.Headers = http.Header{}
	}
	c.Headers[http3.CapsuleProtocolHeader] = []string{capsuleProtocolHeaderValue}

	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: c.Headers,
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("masque: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(rstr, c.conn.LocalAddr()), rsp, nil
}

// Close closes the connection to the proxy.
// This immediately shuts down all proxied flows.
func (c *Client) Close() error {
	c.dialOnce.Do(func() {}) // wait for existing calls to finish
	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	return nil
}

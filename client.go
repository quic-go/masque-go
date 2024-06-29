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

type Client struct {
	// Template is the URI template of the UDP proxy.
	Template *uritemplate.Template

	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the h3 ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	dialOnce sync.Once
	dialErr  error
	conn     quic.Connection
	rt       *http3.SingleDestinationRoundTripper
}

func (c *Client) Dial(ctx context.Context, raddr *net.UDPAddr) (net.PacketConn, error) {
	if c.Template == nil {
		return nil, errors.New("masque: no template")
	}
	str, err := c.Template.Expand(uritemplate.Values{
		uriTemplateTargetHost: uritemplate.String(url.QueryEscape(raddr.IP.String())),
		uriTemplateTargetPort: uritemplate.String(strconv.Itoa(raddr.Port)),
	})
	if err != nil {
		return nil, fmt.Errorf("masque: failed to expand Template: %w", err)
	}
	u, err := url.Parse(str)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to parse URI: %w", err)
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
		c.rt = &http3.SingleDestinationRoundTripper{
			Connection:      conn,
			EnableDatagrams: true,
		}
	})
	if c.dialErr != nil {
		return nil, c.dialErr
	}
	conn := c.rt.Start()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, errors.New("masque: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, errors.New("masque: server didn't enable Datagrams")
	}

	rstr, err := c.rt.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: http.Header{capsuleHeader: []string{capsuleProtocolHeaderValue}},
		URL:    u,
	}); err != nil {
		return nil, fmt.Errorf("masque: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, fmt.Errorf("masque: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, fmt.Errorf("masque: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(rstr, conn.LocalAddr(), raddr), nil
}

func (c *Client) Close() error {
	c.dialOnce.Do(func() {}) // wait for existing calls to finish
	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	return nil
}

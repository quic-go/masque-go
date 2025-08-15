package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
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

// Client establishes proxied UDP connections to remote hosts, using HTTP/3.
// Multiple flows can be proxied via the same connection to the proxy, but all
// requests will be sent to the proxy indicated in the first request.
type Client struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the "h3" ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	dialOnce   sync.Once
	dialErr    error
	conn       *quic.Conn
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

func makeExtConnectRequest(expandedTemplate string) (*http.Request, error) {
	u, err := url.Parse(expandedTemplate)
	if err != nil {
		return nil, fmt.Errorf("masque: failed to parse URI: %w", err)
	}

	return &http.Request{
		Method: http.MethodConnect,
		Host:   u.Host,
		Proto:  ConnectUDP,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue},
		},
		URL: u,
	}, nil
}

type DatagramSender interface {
	SendDatagram(b []byte) error
}

type DatagramReceiver interface {
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// DatagramSendReceiver is the common datagram interface of
// http3.Stream and http3.RequestStream.
type DatagramSendReceiver interface {
	DatagramSender
	DatagramReceiver
	io.Closer
}

var _ DatagramSendReceiver = &http3.Stream{}
var _ DatagramSendReceiver = &http3.RequestStream{}

type H3SettingsMonitor interface {
	ReceivedSettings() <-chan struct{}
	Settings() *http3.Settings
}

var _ H3SettingsMonitor = &http3.Conn{}
var _ H3SettingsMonitor = &http3.ClientConn{}

type H3Connectioner interface {
	Connection() *http3.Conn
}

func getDatagramSendReceiver(w io.Writer) DatagramSendReceiver {
	if streamer, ok := w.(http3.HTTPStreamer); ok {
		return streamer.HTTPStream()
	}

	type httpStreamer interface {
		HTTPStream() DatagramSendReceiver
	}
	if streamer, ok := w.(httpStreamer); ok {
		return streamer.HTTPStream()
	}
	return nil
}

func getH3SettingsMonitor(w io.Writer) H3SettingsMonitor {
	if connectioner, ok := w.(H3Connectioner); ok {
		return connectioner.Connection()
	}

	type h3Connectioner interface {
		Connection() H3SettingsMonitor
	}
	if connectioner, ok := w.(h3Connectioner); ok {
		return connectioner.Connection()
	}
	return nil
}

// H3RequestWriter creates an object analogous to http3.responseWriter,
// but in the upstream direction.
type H3RequestWriter struct {
	*http3.RequestStream
	conn *http3.ClientConn
}

func (w H3RequestWriter) HTTPStream() DatagramSendReceiver {
	return w.RequestStream
}

func (w H3RequestWriter) Connection() H3SettingsMonitor {
	return w.conn
}


func (c *Client) dial(ctx context.Context, expandedTemplate string) (net.PacketConn, *http.Response, error) {
	req, err := makeExtConnectRequest(expandedTemplate)
	if err != nil {
		return nil, nil, err
	}

	c.dialOnce.Do(func() {
		quicConf := c.QUICConfig
		if quicConf == nil {
			quicConf = &quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: defaultInitialPacketSize,
			}
		}
		tlsConf := c.TLSClientConfig
		if tlsConf == nil {
			tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
		}
		conn, err := quic.DialAddr(ctx, req.Host, tlsConf, quicConf)
		if err != nil {
			c.dialErr = fmt.Errorf("masque: dialing QUIC connection failed: %w", err)
			return
		}
		c.conn = conn
		tr := &http3.Transport{EnableDatagrams: quicConf.EnableDatagrams}
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
		log.Printf("masque: server didn't enable Datagrams")
	}

	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(req); err != nil {
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
	w := &H3RequestWriter{rstr, c.clientConn}
	conn := ProxiedPacketConn(w, rsp.Body, c.QUICConfig.EnableDatagrams)
	return conn, rsp, nil
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

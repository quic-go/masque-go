package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// defaultInitialPacketSize is an increased packet size used for the connection to the proxy.
// This allows tunneling QUIC connections, which themselves have a minimum MTU requirement of 1200 bytes.
const defaultInitialPacketSize = 1350

// A Transport establishes proxied connections to multiple remote hosts.
type Transport struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the "h3" ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	// DialAddr dials the QUIC connection to the proxy.
	// If unset, quic.DialAddr is used.
	DialAddr func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)
}

// Dial is a shortcut that opens a QUIC connection to the proxy and then dials a proxied connection.
// Closing the returned Conn also closes the QUIC connection to the proxy.
// More advanced use cases, including multiple proxied connections via one proxy connection,
// should dial a new QUIC connection and use [Transport.NewClientConn].
func (t *Transport) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.req
	if httpReq.URL == nil || httpReq.URL.Host == "" {
		return nil, nil, errors.New("masque: request URL needs a host")
	}

	quicConf := t.QUICConfig
	if quicConf == nil {
		quicConf = &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: defaultInitialPacketSize,
		}
	}
	if !quicConf.EnableDatagrams {
		return nil, nil, errors.New("masque: QUICConfig needs to enable Datagrams")
	}
	tlsConf := t.TLSClientConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	}
	dial := t.DialAddr
	if dial == nil {
		dial = quic.DialAddr
	}
	conn, err := dial(httpReq.Context(), httpReq.URL.Host, tlsConf, quicConf)
	if err != nil {
		return nil, nil, fmt.Errorf("masque: dialing QUIC connection failed: %w", err)
	}
	c, err := t.NewClientConn(conn)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	pconn, rsp, err := c.dial(req, func() error { return conn.CloseWithError(0, "") })
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, rsp, err
	}
	return pconn, rsp, nil
}

// NewClientConn creates a client connection for an already established QUIC connection.
// It returns an error if the QUIC connection didn't negotiate datagram support.
// The caller owns the QUIC connection and closes it when done.
func (t *Transport) NewClientConn(conn *quic.Conn) (*ClientConn, error) {
	if datagrams := conn.ConnectionState().SupportsDatagrams; !datagrams.Local || !datagrams.Remote {
		return nil, errors.New("masque: QUIC connection needs Datagram support")
	}
	tr := &http3.Transport{EnableDatagrams: true}
	return &ClientConn{
		conn:       conn,
		clientConn: tr.NewClientConn(conn),
	}, nil
}

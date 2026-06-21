package masque

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/dunglas/httpsfv"
)

// A ClientConn represents a connection to a single proxy server.
// Multiple proxied connections can be established over a single ClientConn.
type ClientConn struct {
	conn       *quic.Conn
	clientConn *http3.ClientConn
}

// Dial dials a proxied connection to a target server over the proxy connection.
func (c *ClientConn) Dial(req *http.Request) (*Conn, *http.Response, error) {
	return c.dial(req, nil)
}

func (c *ClientConn) dial(req *http.Request, closeConn func() error) (*Conn, *http.Response, error) {
	if req == nil {
		return nil, nil, errors.New("masque: nil request")
	}
	if req.URL == nil {
		return nil, nil, errors.New("masque: request URL is nil")
	}
	if req.Host == "" && req.URL.Host == "" {
		return nil, nil, errors.New("masque: request needs a host")
	}

	select {
	case <-req.Context().Done():
		return nil, nil, context.Cause(req.Context())
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

	rstr, err := c.clientConn.OpenRequestStream(req.Context())
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

	var raddr net.Addr
	if udpAddr := nextHopAddr(rsp); udpAddr != nil {
		raddr = udpAddr
	} else if target, ok := req.Context().Value(requestTargetContextKey{}).(string); ok && target != "" {
		raddr = net.Addr(masqueAddr{target})
	} else {
		raddr = net.Addr(masqueAddr{req.URL.String()})
	}

	return newProxiedConn(rstr, masqueAddr{c.conn.LocalAddr().String()}, raddr, closeConn), rsp, nil
}

// Extract the Proxy-Status next-hop value as a UDPAddr.
func nextHopAddr(rsp *http.Response) *net.UDPAddr {
	proxyStatusVals := rsp.Header.Values("Proxy-Status")
	if len(proxyStatusVals) == 0 {
		return nil
	}
	proxyStatus, err := httpsfv.UnmarshalItem(proxyStatusVals)
	if err != nil {
		log.Printf("bad Proxy-Status: %v", err)
		return nil
	}
	nextHop, ok := proxyStatus.Params.Get("next-hop")
	if !ok {
		return nil
	}
	nextHopStr, ok := nextHop.(string)
	if !ok {
		log.Printf("non-string nextHop value")
		return nil
	}
	if nextHopStr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(nextHopStr)
	if err != nil {
		log.Printf("bad next-hop value: %v", err)
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		log.Printf("bad port: %v", err)
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: portNum}
}

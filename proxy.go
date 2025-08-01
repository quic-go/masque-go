package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	closed atomic.Bool

	mx       sync.Mutex
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	conns    map[proxyEntry]struct{}
}

func errToStatus(err error) int {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			// "Negative response" isn't a real RCODE, but it is included
			// in RFC 8499 Section 3 as a sort of meta/pseudo-RCODE like NODATA,
			// and this section is referenced by the definition of the "rcode"
			// parameter.
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			// DNS intermediaries normally convert miscellaneous errors to SERVFAIL.
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	proxyStatus := httpsfv.NewItem(r.Host)
	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		proxyStatus.Params.Add("details", err.Error())
		proxyStatusVal, _ := httpsfv.Marshal(proxyStatus)
		w.Header().Add("proxy-status", proxyStatusVal)

		w.WriteHeader(errToStatus(err))
		return err
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		proxyStatus.Params.Add("details", err.Error())
		proxyStatusVal, _ := httpsfv.Marshal(proxyStatus)
		w.Header().Add("proxy-status", proxyStatusVal)

		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	proxyStatusVal, _ := httpsfv.Marshal(proxyStatus)
	w.Header().Add("proxy-status", proxyStatusVal)
	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
// It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	if s.closed.Load() {
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()
	s.mx.Lock()
	if s.conns == nil {
		s.conns = make(map[proxyEntry]struct{})
	}
	s.conns[proxyEntry{str: str, conn: conn}] = struct{}{}
	s.mx.Unlock()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if err := s.proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str); err != nil && !s.closed.Load() {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		// discard all capsules sent on the request stream
		if err := skipCapsules(quicvarint.NewReader(str)); err == io.EOF {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
		conn.Close()
	}()
	wg.Wait()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str *http3.Stream) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return err
		}
		if contextID != 0 {
			// Drop this datagram. We currently only support proxying of UDP payloads.
			continue
		}
		if _, err := conn.Write(data[n:]); err != nil {
			return err
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
	b := make([]byte, 1500)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return err
		}
		data := make([]byte, 0, len(contextIDZero)+n)
		data = append(data, contextIDZero...)
		data = append(data, b[:n]...)
		if err := str.SendDatagram(data); err != nil {
			return err
		}
	}
}

// Close closes the proxy, immeidately terminating all proxied flows.
func (s *Proxy) Close() error {
	s.closed.Store(true)
	s.mx.Lock()
	for entry := range s.conns {
		entry.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		entry.str.Close()
		entry.conn.Close()
	}
	s.conns = nil
	s.mx.Unlock()
	s.refCount.Wait()
	return nil
}

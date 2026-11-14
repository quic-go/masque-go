package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const maxUDPPayloadSize = 1500

var contextIDZero = quicvarint.Append([]byte{}, 0)

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct{}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Consistent with RFC 9209 Section 2.3.1.
		return http.StatusGatewayTimeout
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		// Recommended by RFC 9209 Section 2.3.2.
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
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
// It returns when the client closes the request stream, or when the context is canceled.
func (s *Proxy) Proxy(ctx context.Context, w http.ResponseWriter, r *ProxyRequest) error {
	if err := context.Cause(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return err
	}

	proxyStatus := httpsfv.NewItem(r.Host)
	// Adds the proxy status to the header.  Returns
	// the input error, or a new one if serialization fails.
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		if dnsError, ok := errors.AsType[*net.DNSError](err); ok {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	if err = writeProxyStatus(nil); err != nil {
		w.WriteHeader(errToStatus(err))
		return err
	}
	return s.ProxyConnectedSocket(ctx, w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
// It returns when the client closes the request stream, or when the context is canceled.
func (s *Proxy) ProxyConnectedSocket(ctx context.Context, w http.ResponseWriter, _ *ProxyRequest, conn *net.UDPConn) error {
	if err := context.Cause(ctx); err != nil {
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return err
	}

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)
	str, err := w.(http3.HTTPStreamer).HTTPStream()
	if err != nil {
		conn.Close()
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.proxyConnSend(ctx, conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		// unblocks skipCapsules
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str); err != nil && ctx.Err() == nil {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	// discard all capsules sent on the request stream
	if err := skipCapsules(str); err == io.EOF {
		log.Printf("reading from request stream failed: %v", err)
	}
	str.Close()
	conn.Close()
	wg.Wait()
	return nil
}

func (s *Proxy) proxyConnSend(ctx context.Context, conn *net.UDPConn, str *http3.Stream) error {
	for {
		data, err := str.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
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
		if len(data[n:]) > maxUDPPayloadSize {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUDPPayloadSize)
			continue
		}
		if _, err := conn.Write(data[n:]); err != nil {
			return err
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str *http3.Stream) error {
	b := make([]byte, len(contextIDZero)+maxUDPPayloadSize+1)
	copy(b, contextIDZero)
	for {
		n, err := conn.Read(b[len(contextIDZero):])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		if err := str.SendDatagram(b[:len(contextIDZero)+n]); err != nil {
			return err
		}
	}
}

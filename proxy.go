package masque

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const maxUDPPayloadSize = 1500

var contextIDZero = quicvarint.Append([]byte{}, 0)

type proxyEntry struct {
	str  *http3.Stream
	conn *net.UDPConn
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers  map[io.Closer]struct{}
}

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
func (s *Proxy) Proxy(w http.ResponseWriter, r *ProxyRequest) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

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
	return s.ProxyConnectedSocket(w, r, conn)
}

func writeResponseWithHijacker(headers http.Header, httpConn net.Conn, buf *bufio.ReadWriter, protocol string) error {
	statusCode := http.StatusSwitchingProtocols
	if buf.Reader.Buffered() > 0 {
		statusCode = http.StatusBadRequest
		if proxyStatusVals := headers.Values("Proxy-Status"); len(proxyStatusVals) > 0 {
			proxyStatus, err := httpsfv.UnmarshalItem(proxyStatusVals)
			if err != nil {
				return fmt.Errorf("encountered invalid Proxy-Status: %w", err)
			}
			proxyStatus.Params.Add("error", "proxy_internal_response")
			proxyStatus.Params.Add("detail",
				fmt.Sprintf("client sent %d bytes of optimistic data, not allowed in HTTP/1.1", buf.Reader.Buffered()))
			newProxyStatusVal, err := httpsfv.Marshal(proxyStatus)
			if err != nil {
				return fmt.Errorf("couldn't serialize Proxy-Status: %w", err)
			}
			headers.Set("Proxy-Status", newProxyStatusVal)
		}
	}

	rsp := http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: -1,
		Header:        headers,
	}
	if statusCode == http.StatusSwitchingProtocols {
		rsp.Header.Set("Connection", "Upgrade")
		if rsp.Header.Get("Upgrade") == "" {
			rsp.Header.Set("Upgrade", protocol)
		}
	}
	rspBytes, err := httputil.DumpResponse(&rsp, false)
	if err != nil {
		return err
	}
	if _, err := httpConn.Write(rspBytes); err != nil {
		return err
	}
	return nil
}

func (s *Proxy) proxyH1(w http.ResponseWriter, conn *net.UDPConn) error {
	h1Conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		conn.Close()
		return err
	}
	defer h1Conn.Close()

	upgradeProtocol := requestProtocol
	if reqUpgrade := w.Header().Get("Upgrade"); reqUpgrade != "" {
		upgradeProtocol = reqUpgrade
	}
	if err := writeResponseWithHijacker(w.Header(), h1Conn, buf, upgradeProtocol); err != nil {
		conn.Close()
		return err
	}

	s.mx.Lock()
	// the proxy might have been closed while sending the response header
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		return net.ErrClosed
	}
	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[h1Conn] = struct{}{}
	s.mx.Unlock()

	forwardUDP(nil, h1Conn, h1Conn, conn)

	s.mx.Lock()
	delete(s.closers, h1Conn)
	s.mx.Unlock()
	return nil
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, r *ProxyRequest, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)

	if r != nil && r.ProtoMajor == 1 {
		return s.proxyH1(w, conn)
	}
	if r != nil && r.ProtoMajor != 0 && r.ProtoMajor != 3 {
		conn.Close()
		w.WriteHeader(http.StatusNotImplemented)
		return fmt.Errorf("masque: unsupported HTTP version: %d", r.ProtoMajor)
	}

	w.WriteHeader(http.StatusOK)

	// Sending the response header might block on flow control,
	// so this must not be done while holding the mutex.
	str, err := w.(http3.HTTPStreamer).HTTPStream()
	if err != nil {
		conn.Close()
		return err
	}
	entry := proxyEntry{str: str, conn: conn}

	s.mx.Lock()
	// the proxy might have been closed while sending the response header
	if s.closed {
		s.mx.Unlock()
		entry.Close()
		return net.ErrClosed
	}
	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}
	s.mx.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := proxyConnSend(conn, str); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := proxyConnReceive(conn, str); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
			}
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
	s.mx.Lock()
	delete(s.closers, entry)
	s.mx.Unlock()
	return nil
}

func proxyConnSend(conn io.Writer, str DatagramReceiver) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
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

func proxyConnReceive(conn io.Reader, str DatagramSender) error {
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

// Close closes the proxy, immediately terminating all proxied flows.
func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return errors.Join(errs...)
}

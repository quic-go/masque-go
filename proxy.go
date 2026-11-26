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

const (
	maxUDPPayloadSize       = 1500
	maxContextIDZeroPayload = 65527
)

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

type h1ProxyEntry struct {
	closer io.Closer
}

func (e *h1ProxyEntry) Close() error {
	return e.closer.Close()
}

func writeResponseWithHijacker(headers http.Header, httpConn net.Conn, buf *bufio.ReadWriter, protocol string) error {
	statusCode := http.StatusSwitchingProtocols
	var requestError error
	// RFC 9931 Section 6.3: Clients MUST NOT send UDP packets optimistically in HTTP/1.x
	// due to the risk of Request Smuggling attacks.
	if buf.Reader.Buffered() > 0 {
		statusCode = http.StatusBadRequest
		requestError = errors.New("client sent optimistic data")
		if proxyStatusVals := headers.Values("Proxy-Status"); len(proxyStatusVals) > 0 {
			if list, err := httpsfv.UnmarshalList(proxyStatusVals); err == nil && len(list) > 0 {
				if last, ok := list[len(list)-1].(httpsfv.Item); ok {
					last.Params.Add("error", "proxy_internal_response")
					last.Params.Add("details",
						fmt.Sprintf("client sent %d bytes of optimistic data, not allowed in HTTP/1.1", buf.Reader.Buffered()))
					list[len(list)-1] = last
					if newProxyStatusVal, err := httpsfv.Marshal(list); err == nil {
						headers.Set("Proxy-Status", newProxyStatusVal)
					}
				}
			}
		}
	}

	rsp := http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
	}
	if statusCode == http.StatusSwitchingProtocols {
		rsp.Header.Set("Connection", "Upgrade")
		if rsp.Header.Get("Upgrade") == "" {
			rsp.Header.Set("Upgrade", protocol)
		}
		rsp.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
		// RFC 9297 Section 3.2: Capsule Protocol responses must not contain
		// Content-Length, Content-Type, or Transfer-Encoding.
		rsp.Header.Del("Content-Length")
		rsp.Header.Del("Content-Type")
		rsp.Header.Del("Transfer-Encoding")
	} else {
		// RFC 9297 Section 3.4: Capsule-Protocol MUST NOT be used on responses
		// other than 101 or 2xx.
		rsp.Header.Del(http3.CapsuleProtocolHeader)
		rsp.Close = true
	}
	rspBytes, err := httputil.DumpResponse(&rsp, false)
	if err != nil {
		return err
	}
	if _, err := httpConn.Write(rspBytes); err != nil {
		return err
	}

	return requestError
}

func (s *Proxy) proxyH1(w http.ResponseWriter, conn *net.UDPConn) error {
	h1Conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		conn.Close()
		return err
	}
	closer := &sharedCloser{c: h1Conn}
	defer closer.Close()

	if err := writeResponseWithHijacker(w.Header(), h1Conn, buf, requestProtocol); err != nil {
		conn.Close()
		return err
	}

	entry := &h1ProxyEntry{closer: closer}

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
	s.closers[entry] = struct{}{}
	s.mx.Unlock()

	h1Writer := struct {
		io.Writer
		io.Closer
	}{h1Conn, closer}
	h1Reader := struct {
		*bufio.Reader
		io.Closer
	}{buf.Reader, closer}
	_ = forwardUDP(nil, h1Writer, h1Reader, conn)

	s.mx.Lock()
	delete(s.closers, entry)
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

	if r != nil && r.ProtoMajor == 1 {
		return s.proxyH1(w, conn)
	}
	if r != nil && r.ProtoMajor != 0 && r.ProtoMajor != 3 {
		conn.Close()
		w.WriteHeader(http.StatusNotImplemented)
		return fmt.Errorf("masque: unsupported HTTP version: %d", r.ProtoMajor)
	}

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
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
		if err := proxyConnSend(conn, http3DatagramReceiver{str}); err != nil {
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

// readUDPDatagramHeader reads the Context ID from dgram and validates the
// remaining UDP payload size according to RFC 9298 Section 5.
// It returns ok=false when the datagram should be silently dropped (unknown
// Context ID or payload exceeding maxSize when maxSize > 0), discarding any
// unread bytes without buffering them.
func readUDPDatagramHeader(dgram datagramReader, maxSize int64) (payloadLen int64, ok bool, err error) {
	contextID, err := quicvarint.Read(dgram)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, false, io.ErrUnexpectedEOF
		}
		return 0, false, err
	}
	rem := dgram.Remaining()
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of UDP payloads.
		if err := dgram.Discard(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	// RFC 9298 Section 5: an endpoint that receives an HTTP Datagram using
	// Context ID zero whose UDP Proxying Payload field is longer than 65527
	// MUST abort the corresponding stream.
	if rem > maxContextIDZeroPayload {
		return 0, false, fmt.Errorf("masque: UDP datagram payload too large (%d > %d)", rem, maxContextIDZeroPayload)
	}
	if maxSize > 0 && rem > maxSize {
		log.Printf("dropping datagram larger than MTU (%d > %d)", rem, maxSize)
		if err := dgram.Discard(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	return rem, true, nil
}

func proxyConnSend(conn io.Writer, recv datagramStreamReceiver) error {
	buf := make([]byte, maxUDPPayloadSize)
	for {
		dgram, err := recv.NextDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		rem, ok, err := readUDPDatagramHeader(dgram, maxUDPPayloadSize)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if _, err := io.ReadFull(dgram, buf[:rem]); err != nil {
			return err
		}
		if _, err := conn.Write(buf[:rem]); err != nil {
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

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

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"

	datagramCapsuleType = 0x00

	maxUdpPayload = 1500
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
	// EnableDatagrams must match QUICConfig.EnableDatagrams,
	// Transport.EnableDatagrams, and Settings.EnableDatagrams.
	// It is required here because there is no way to recover the QUICConfig,
	// Transport, or local Settings from the request or response.
	EnableDatagrams bool

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
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
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
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
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
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
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

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	str := w.(http3.HTTPStreamer).HTTPStream()
	entry := proxyEntry{str: str, conn: conn}

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[entry] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var dgs DatagramSendReceiver
	if s.EnableDatagrams && clientAcceptsDatagrams(w) {
		dgs = str
	}
	forwardUDP(dgs, w, str, conn)
	str.Close()

	s.mx.Lock()
	delete(s.closers, entry)
	s.mx.Unlock()
	return nil
}

// Returns true if the client has offered to receive datagrams.
func clientAcceptsDatagrams(w http.ResponseWriter) bool {
	hijacker, ok := w.(http3.Hijacker)
	if !ok {
		return false
	}

	h3Connection := hijacker.Connection()
	<-h3Connection.ReceivedSettings()
	remoteSettings := h3Connection.Settings()
	return remoteSettings.EnableDatagrams
}

/*
 * Forwarding function conventions:
 * `*To*` functions block until that direction of forwarding is complete.
 * They return `nil` (not EOF) on clean shutdown.
 * `str`, `w`, and `r` represent the HTTP side.
 * `conn` represents the raw UDP or TCP side.
 */

// `r`, `w`, and `conn` are required.
// `str` indicates Datagram support if non-nil.
func forwardUDP(str DatagramSendReceiver, w io.Writer, r io.ReadCloser, conn net.Conn) {
	var wg sync.WaitGroup
	defer wg.Wait()
	if str != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := udpToDatagrams(str, conn); err != nil {
				log.Printf("proxying %s to datagrams stopped: %v", conn.RemoteAddr(), err)
			}
			r.Close()
		}()
		go func() {
			defer wg.Done()
			if err := datagramsToUDP(conn, str); err != nil {
				log.Printf("proxying datagrams to %s failed: %v", conn.RemoteAddr(), err)
			}
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := udpToCapsules(w, conn); err != nil {
				log.Printf("writing to HTTP stream failed: %v", err)
			}
			r.Close()
		}()
	}

	// The remote peer can always choose to send capsules.
	if err := capsulesToUDP(conn, r); err != nil {
		log.Printf("reading from HTTP stream failed: %v", err)
	}
	conn.Close()
}

func datagramsToUDP(conn io.Writer, str DatagramReceiver) error {
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
		if len(data[n:]) > maxUdpPayload {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUdpPayload)
			continue
		}
		if _, err := conn.Write(data[n:]); err != nil {
			return err
		}
	}
}

func udpToDatagrams(str DatagramSender, conn io.Reader) error {
	b := make([]byte, len(contextIDZero)+maxUdpPayload+1)
	copy(b, contextIDZero)
	payloadBuf := b[len(contextIDZero):]
	for {
		n, err := conn.Read(payloadBuf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUdpPayload {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		data := b[:len(contextIDZero)+n]
		if err := str.SendDatagram(data); err != nil {
			return err
		}
	}
}

func capsulesToUDP(conn io.Writer, body io.Reader) error {
	qr := quicvarint.NewReader(body)
	b := make([]byte, maxUdpPayload+1)
	for {
		capsuleType, content, err := http3.ParseCapsule(qr)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if capsuleType != datagramCapsuleType {
			log.Printf("skipping unknown capsule type %d", capsuleType)
			continue
		}
		n, err := readAll(content, b)
		if n > maxUdpPayload {
			// Drain remainder of oversize capsule
			remainder, err := io.Copy(io.Discard, content)
			if err != nil {
				return err
			}
			log.Printf("skipped datagram capsule larger than MTU (%d > %d)", int64(n)+remainder, maxUdpPayload)
			continue
		}
		if err != nil {
			return err
		}
		if _, err := conn.Write(b[:n]); err != nil {
			return err
		}
	}
}

// Read all the data from r until EOF.  If this doesn't fit in b,
// ErrShortBuffer is returned.
func readAll(r io.Reader, b []byte) (int, error) {
	blen := 0
	for blen < len(b) {
		n, err := r.Read(b[blen:])
		blen += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return blen, nil
			}
			return blen, err
		}
	}
	return blen, io.ErrShortBuffer
}

func udpToCapsules(w io.Writer, conn io.Reader) error {
	qw := quicvarint.NewWriter(w)
	b := make([]byte, maxUdpPayload+1)
	for {
		n, err := conn.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUdpPayload {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		if err := http3.WriteCapsule(qw, datagramCapsuleType, b[:n]); err != nil {
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

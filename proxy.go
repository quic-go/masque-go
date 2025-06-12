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
	"github.com/yosida95/uritemplate/v3"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"

	datagramCapsuleType = 0x00

	maxUdpPayload = 1500

	// Limits the size of downstream TCP capsules
	maxTCPChunkSize = 32 * 1024 // 32KB, somewhat arbitrary

	data08CapsuleType      = 0x2028d7f0
	finalData08CapsuleType = 0x2028d7f1

	H3_CONNECT_ERROR = 0x010f // RFC 9114

)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type proxyEntry struct {
	rsp http.ResponseWriter
	req io.ReadCloser
}

func (e proxyEntry) Close() error {
	if streamer, isH3 := e.rsp.(http3.HTTPStreamer); isH3 {
		str := streamer.HTTPStream()
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	}

	return e.req.Close()
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	Template        *uritemplate.Template
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
func (s *Proxy) Proxy(w http.ResponseWriter, r *http.Request) error {
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

	req, err := ParseRequest(r, s.Template)
	if err != nil {
		var perr *RequestParseError
		if errors.As(err, &perr) {
			w.WriteHeader(perr.HTTPStatus)
			return nil
		}
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	if req.Protocol == ConnectUDP {
		addr, err := net.ResolveUDPAddr("udp", req.Target)
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

		if err := writeProxyStatus(nil); err != nil {
			w.WriteHeader(errToStatus(err))
			return err
		}

		return s.ProxyConnectedSocket(w, req, conn)
	}
	return fmt.Errorf("unknown protocol %q", req.Protocol)
}

func hijackIfH1(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, isH1 := w.(http.Hijacker)
	if !isH1 {
		return nil, nil, nil
	}
	return hijacker.Hijack()
}

func writeResponseWithHijacker(headers http.Header, httpConn net.Conn, buf *bufio.ReadWriter, protocol string) error {
	statusCode := http.StatusSwitchingProtocols
	if buf.Reader.Buffered() > 0 {
		// CONNECT-TCP Section 4.1 says 'Clients MUST NOT use "optimistic" behavior in HTTP/1.1'.
		statusCode = http.StatusBadRequest
		if proxyStatusVals := headers.Values("Proxy-Status"); len(proxyStatusVals) > 0 {
			proxyStatus, err := httpsfv.UnmarshalItem(proxyStatusVals)
			if err != nil {
				return fmt.Errorf("encountered invalid Proxy-Status: %w", err)
			}
			proxyStatus.Params.Add("error", "proxy_internal_response")
			proxyStatus.Params.Add("detail",
				fmt.Sprintf("client sent %d bytes of optimistic data, not allowed in HTTP/1.1", buf.Available()))
			newProxyStatusVal, err := httpsfv.Marshal(proxyStatus)
			if err != nil {
				return fmt.Errorf("Couldn't serialize Proxy-Status: %w", err)
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
		rsp.Header.Set("Upgrade", protocol)
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

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, r *Request, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	var closer io.Closer = proxyEntry{rsp: w, req: r.Body}

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[closer] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	h1Conn, buf, err := hijackIfH1(w)
	if err != nil {
		return err
	}
	if h1Conn != nil {
		defer h1Conn.Close()

		// The request body is no longer relevant due to hijack.  Use the
		// hijacked connection instead.
		s.mx.Lock()
		delete(s.closers, closer)
		closer = h1Conn
		s.closers[closer] = struct{}{}
		s.mx.Unlock()

		if err := writeResponseWithHijacker(w.Header(), h1Conn, buf, ConnectUDP); err != nil {
			return err
		}

		forwardUDP(h1Conn, h1Conn, conn, false)
	} else {
		w.WriteHeader(http.StatusOK)
		forwardUDP(w, r.Body, conn, s.EnableDatagrams)
	}

	s.mx.Lock()
	delete(s.closers, closer)
	s.mx.Unlock()
	return nil
}

/*
 * Forwarding function conventions:
 * `*To*` functions block until that direction of forwarding is complete.
 * They return `nil` (not EOF) on clean shutdown.
 * `w` and `r` represent the HTTP side.
 * `conn` represents the raw UDP or TCP side.
 */

type H3Streamer interface {
	http3.HTTPStreamer
	Connection() *http3.Conn
}

func forwardUDP(w io.Writer, r io.ReadCloser, conn net.Conn, enableDatagrams bool) {
	var wg sync.WaitGroup
	defer wg.Wait()
	useDatagrams := false
	str := getDatagramSendReceiver(w)
	if str != nil {
		defer str.Close()
		if enableDatagrams {
			h3Connection := getH3SettingsMonitor(w)
			<-h3Connection.ReceivedSettings()
			remoteSettings := h3Connection.Settings()
			useDatagrams = remoteSettings.EnableDatagrams
		}
	}
	if useDatagrams {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := datagramsToUDP(conn, str); err != nil {
				log.Printf("proxying datagrams to %s failed: %v", conn.RemoteAddr(), err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := udpToDatagrams(conn, str); err != nil {
				log.Printf("proxying %s to datagrams stopped: %v", conn.RemoteAddr(), err)
			}
			// Backup shutdown: `conn` somehow became closed or a datagram write failed.
			r.Close()
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := udpToCapsules(conn, w); err != nil {
				log.Printf("writing to HTTP stream failed: %v", err)
			}
			// Backup shutdown: `conn` somehow became closed or an HTTP write failed.
			r.Close()
		}()
	}

	// Wait for the client to close the upstream side.
	if err := capsulesToUDP(conn, r); err != nil {
		log.Printf("reading from HTTP stream failed: %v", err)
	}
	// Normal shutdown: client closes the request stream, so we
	// close the UDP connection.
	conn.Close()
}

func datagramsToUDP(conn io.Writer, str DatagramReceiver) error {
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
		if len(data[n:]) > maxUdpPayload {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUdpPayload)
		}
		if _, err := conn.Write(data[n:]); err != nil {
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

func capsulesToUDP(conn io.Writer, body io.Reader) error {
	qr := quicvarint.NewReader(body)
	b := make([]byte, maxUdpPayload)
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
		if err == io.ErrShortBuffer {
			// Drain remainder of oversize capsule
			n, err := io.Copy(io.Discard, content)
			if err != nil {
				return err
			}
			log.Printf("skipping datagram capsule larger than MTU (%d > %d)", n+maxUdpPayload, maxUdpPayload)
		}
		if err != nil {
			return err
		}
		if _, err := conn.Write(b[:n]); err != nil {
			return err
		}
	}
}

func udpToDatagrams(conn io.Reader, str DatagramSender) error {
	b := make([]byte, len(contextIDZero)+maxUdpPayload)
	copy(b, contextIDZero)
	for {
		n, err := conn.Read(b[len(contextIDZero):])
		if err != nil {
			return err
		}
		data := b[:len(contextIDZero)+n]
		if err := str.SendDatagram(data); err != nil {
			return err
		}
	}
}

func udpToCapsules(conn io.Reader, w io.Writer) error {
	qw := quicvarint.NewWriter(w)
	b := make([]byte, maxUdpPayload)
	for {
		n, err := conn.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
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

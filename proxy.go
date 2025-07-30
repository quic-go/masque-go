package masque

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers  map[io.Closer]struct{}
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

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		// TODO(#2): set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
	// TODO(#2): set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}
	defer conn.Close()

	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
// It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, r *Request, conn *net.UDPConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}
	s.closers[r.Body] = struct{}{}

	s.refCount.Add(1)
	defer s.refCount.Done()
	s.mx.Unlock()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()

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
		if err := s.proxyConnReceive(conn, str); err != nil {
			s.mx.Lock()
			closed := s.closed
			s.mx.Unlock()
			if !closed {
				log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
			}
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
	s.mx.Lock()
	delete(s.closers, r.Body)
	s.mx.Unlock()
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
	s.mx.Lock()
	s.closed = true
	for c := range s.closers {
		c.Close()
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return nil
}

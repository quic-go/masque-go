package masque

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

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
	str  http3.Stream
	conn *net.UDPConn
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	closed atomic.Bool

	mx       sync.Mutex
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	conns    map[proxyEntry]struct{}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request, tracer *Tracer) error {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

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

	return s.ProxyConnectedSocket(w, conn, tracer)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
// It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, conn *net.UDPConn, tracer *Tracer) error {
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
		if err := s.proxyConnSend(conn, str, tracer); err != nil {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		if tracer != nil && tracer.SendDirectionClosed != nil {
			tracer.SendDirectionClosed()
		}
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str, tracer); err != nil && !s.closed.Load() {
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
		if tracer != nil && tracer.ReceiveDirectionClosed != nil {
			tracer.ReceiveDirectionClosed()
		}
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

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str http3.Stream, tracer *Tracer) error {
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
		b := data[n:]
		if _, err := conn.Write(b); err != nil {
			return err
		}
		if tracer != nil && tracer.SentData != nil {
			tracer.SentData(len(b))
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str http3.Stream, tracer *Tracer) error {
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
		if tracer != nil && tracer.ReceivedData != nil {
			tracer.ReceivedData(n)
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

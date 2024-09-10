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

type Stats struct {
	PacketsSent, PacketsReceived uint64
	DataSent, DataReceived       uint64
}

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
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) (Stats, error) {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return Stats{}, net.ErrClosed
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		// TODO: set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return Stats{}, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		// TODO: set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return Stats{}, err
	}
	defer conn.Close()

	return s.ProxyConnectedSocket(w, r, conn)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) (Stats, error) {
	if s.closed.Load() {
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return Stats{}, net.ErrClosed
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	w.Header().Set(capsuleHeader, capsuleProtocolHeaderValue)
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
	var packetsSent, packetsReceived, dataSent, dataReceived uint64
	go func() {
		defer wg.Done()
		var err error
		packetsSent, dataSent, err = s.proxyConnSend(conn, str)
		if err != nil && !s.closed.Load() {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		var err error
		packetsReceived, dataReceived, err = s.proxyConnReceive(conn, str)
		if err != nil && !s.closed.Load() {
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
	return Stats{
		PacketsSent:     packetsSent,
		PacketsReceived: packetsReceived,
		DataSent:        dataSent,
		DataReceived:    dataReceived,
	}, nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str http3.Stream) (packetsSent, dataSent uint64, _ error) {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			return packetsSent, dataSent, err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return packetsSent, dataSent, err
		}
		if contextID != 0 {
			// Drop this datagram. We currently only support proxying of UDP payloads.
			continue
		}
		packetsSent++
		dataSent += uint64(len(data) - n)
		if _, err := conn.Write(data[n:]); err != nil {
			return packetsSent, dataSent, err
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str http3.Stream) (packetsReceived, dataReceived uint64, _ error) {
	b := make([]byte, 1500)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return packetsReceived, dataReceived, err
		}
		packetsReceived++
		dataReceived += uint64(n)
		data := make([]byte, 0, len(contextIDZero)+n)
		data = append(data, contextIDZero...)
		data = append(data, b[:n]...)
		if err := str.SendDatagram(data); err != nil {
			return packetsReceived, dataReceived, err
		}
	}
}

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

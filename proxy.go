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

	compressionTable *compressionTable
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

func (s *Proxy) ProxyListen(w http.ResponseWriter, r *Request, laddr *net.UDPAddr) error {
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		// TODO(#2): set proxy-status header (might want to use structured headers)
		w.WriteHeader(http.StatusGatewayTimeout)
		return err
	}
	defer conn.Close()

	s.compressionTable = newCompressionTable(false)

	return s.proxyConnectedSocket(w, conn, true)
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
// It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, _ *Request, conn *net.UDPConn) error {
	return s.proxyConnectedSocket(w, conn, false)
}

// TODO: Should isListen be replaced by Request.Bind?
func (s *Proxy) proxyConnectedSocket(w http.ResponseWriter, conn *net.UDPConn, isListening bool) error {
	if s.closed.Load() {
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	if isListening {
		laddr := conn.LocalAddr().String()
		v, err := httpsfv.Marshal(httpsfv.List{httpsfv.NewItem(laddr)})
		if err != nil {
			// TODO(#2): set proxy-status header (might want to use structured headers)
			w.WriteHeader(http.StatusServiceUnavailable)
			return nil
		}
		w.Header().Set(ProxyPublicAddressHeader, v)
		w.Header().Set(ConnectUDPBindHeader, sfTrueValue)
	}

	w.Header().Set(http3.CapsuleProtocolHeader, sfTrueValue)
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
		if err := s.proxyConnSend(conn, str, isListening); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("proxying send side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.proxyConnReceive(conn, str, isListening); err != nil && !s.closed.Load() {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Printf("proxying receive side to %s failed: %v", conn.RemoteAddr(), err)
		}
		str.Close()
	}()
	go func() {
		defer wg.Done()
		if err := s.processCapsule(str, isListening); err != io.EOF {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
		conn.Close()
	}()
	wg.Wait()
	return nil
}

func (s *Proxy) proxyConnSend(conn *net.UDPConn, str http3Stream, isListening bool) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return err
		}

		if isListening {
			if contextID == 0 {
				// Context ID 0 must be ignored.
				continue
			}

			addr, found := s.compressionTable.lookupContextID(contextID)
			if !found {
				// Context ID is not registered. Drop the datagram.
				continue
			}

			log.Printf("proxy: received datagram (context ID: %d, isCompressed: %t)", contextID, addr != nil)

			if addr == nil {
				// Context ID is used for uncompressed datagrams.
				dg := uncompressedDatagram{}
				err := dg.Unmarshal(data[n:])
				if err != nil {
					return err
				}
				if _, err := conn.WriteTo(dg.Data, dg.Addr); err != nil {
					return err
				}
				continue
			} else {
				// Context ID is used for compressed datagrams. Write the entire data in the datagram
				if _, err := conn.WriteTo(data[n:], addr); err != nil {
					return err
				}
				continue
			}
		} else {
			if contextID != 0 {
				// Drop this datagram. We currently only support proxying of UDP payloads.
				continue
			}
			if _, err := conn.Write(data[n:]); err != nil {
				return err
			}
		}
	}
}

func (s *Proxy) proxyConnReceive(conn *net.UDPConn, str http3Stream, isListening bool) error {
	b := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			return err
		}

		var data []byte
		if !isListening {
			data = make([]byte, 0, len(contextIDZero)+n)
			data = append(data, contextIDZero...)
			data = append(data, b[:n]...)
		} else {
			contextID, isCompressed, found := s.compressionTable.lookupAddr(addr.(*net.UDPAddr))
			if !found {
				log.Printf("proxy: dropping outgoing datagram because no context ID is assigned to %s", addr.String())
				continue
			}

			if !isCompressed {
				dg := uncompressedDatagram{
					Addr: addr.(*net.UDPAddr),
					Data: b[:n],
				}
				data, err = dg.Marshal()
				if err != nil {
					return err
				}
			} else {
				data = b[:n]
			}

			log.Printf("proxy: sending datagram (context ID: %d, isCompressed: %t)", contextID, isCompressed)

			data = prependContextID(data, contextID)
		}

		if err := str.SendDatagram(data); err != nil {
			return err
		}
	}
}

// TODO: Make this reusable to the proxiedConn.
func (s *Proxy) processCapsule(str http3Stream, isListening bool) error {
	reader := quicvarint.NewReader(str)
	writer := quicvarint.NewWriter(str)
	for {
		ct, r, err := http3.ParseCapsule(reader)
		if err != nil {
			return err
		}

		if !isListening {
			log.Printf("skipping capsule of type %d", ct)
			if _, err := io.Copy(io.Discard, r); err != nil {
				return err
			}
			continue
		}

		if ct == compressionAsignCapsuleType {
			p, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			capsule := compressionAssignCapsule{}
			if err := capsule.Unmarshal(p); err != nil {
				return err
			}

			log.Printf("proxy: received COMPRESSION_ASSIGN capsule (context ID: %d, addr: %s)\n", capsule.ContextID, capsule.Addr.String())

			if capsule.ContextID == 0 {
				// Context ID 0 cannot be assigned.
				// TODO: Should this be mentioned in the draft?
				log.Printf("proxy: ignoring assigment of context ID 0")
				continue
			}

			if err := s.compressionTable.handleAssignmentCapsule(capsule); err != nil {
				// TODO: Send COMPRESSION_CLOSE capsule.
				log.Printf("proxy: ignoring assigment of context ID %d to %s: %v", capsule.ContextID, capsule.Addr.String(), err)
			} else {
				// TODO: Send COMPRESSION_ASSIGN capsule.
				log.Printf("proxy: assigned context ID %d to addr %s", capsule.ContextID, capsule.Addr.String())

				responseCapsule := compressionAssignCapsule{
					ContextID: capsule.ContextID,
					Addr:      capsule.Addr,
				}
				data, err := responseCapsule.Marshal()
				if err != nil {
					return err
				}
				err = http3.WriteCapsule(writer, compressionAsignCapsuleType, data)
				if err != nil {
					return err
				}
			}
		} else if ct == compressionCloseCapsuleType {
			p, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			capsule := compressionCloseCapsule{}
			if err := capsule.Unmarshal(p); err != nil {
				return err
			}

			log.Printf("proxy: received COMPRESSION_CLOSE capsule (context ID: %d)", capsule.ContextID)
		} else {
			log.Printf("proxy: ignoring unknown capsule type: 0x%X", ct)
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

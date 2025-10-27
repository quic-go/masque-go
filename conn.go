package masque

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

// Avoid allocating a buffer for each packet.
var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPPayloadSize)
		return &buf
	},
}

// packetConnWrapper converts a [net.Conn] from [net.Pipe]
// into a [net.PacketConn] that can only be used for a single
// destination.  The pipe is presumed to carry writes of
// at most [maxUDPPayloadSize] bytes.
type packetConnWrapper struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (p packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p packetConnWrapper) LocalAddr() net.Addr {
	return p.localAddr
}

func (p packetConnWrapper) RemoteAddr() net.Addr {
	return p.remoteAddr
}

func (p packetConnWrapper) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

func (p packetConnWrapper) Read(b []byte) (int, error) {
	if len(b) >= maxUDPPayloadSize {
		return p.Conn.Read(b)
	}
	// Ensure UDP-style truncation behavior when len(b) < maxUDPPayloadSize.
	// Otherwise, large payloads would be fragmented instead of truncated.
	buf := udpBufPool.Get().(*[]byte)
	n, err := p.Conn.Read(*buf)
	n = copy(b, (*buf)[:n])
	udpBufPool.Put(buf)
	return n, err
}

func (p packetConnWrapper) Write(b []byte) (int, error) {
	if len(b) > maxUDPPayloadSize {
		// net.Conn may fragment large writes instead of dropping them.
		log.Printf("Dropping oversize UDP write")
		return len(b), nil
	}
	return p.Conn.Write(b)
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic [net.PacketConn] of UDP packets.
//
// When the PacketConn is closed, the request and response streams will be closed.
func ProxiedPacketConn(str DatagramSendReceiver, rsp io.ReadCloser, laddr, raddr net.Addr) net.PacketConn {
	left, right := net.Pipe()

	go func() {
		forwardUDP(str, rsp, right)
		str.Close()
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	}()
	return packetConnWrapper{Conn: left, localAddr: laddr, remoteAddr: raddr}
}

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}

package masque

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

// Avoid allocating a buffer for each packet.
var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUdpPayload)
		return &buf
	},
}

// packetConnWrapper converts a [net.Conn] from [net.Pipe]
// into a [net.PacketConn] that can only be used for a single
// destination.  The pipe is presumed to carry writes of
// at most [maxUdpPayload] bytes.
type packetConnWrapper struct {
	net.Conn
	local, remote net.Addr
}

func (p packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p packetConnWrapper) LocalAddr() net.Addr {
	return p.local
}

func (p packetConnWrapper) RemoteAddr() net.Addr {
	return p.remote
}

func (p packetConnWrapper) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

func (p packetConnWrapper) Read(b []byte) (int, error) {
	if len(b) >= maxUdpPayload {
		return p.Conn.Read(b)
	}
	// Ensure UDP-style truncation behavior when len(b) < maxUdpPayload.
	buf := udpBufPool.Get().(*[]byte)
	n, err := p.Conn.Read(*buf)
	n = copy(b, (*buf)[:n])
	udpBufPool.Put(buf)
	return n, err
}

func (p packetConnWrapper) Write(b []byte) (int, error) {
	if len(b) > maxUdpPayload {
		// net.Conn may fragment large writes instead of dropping them.
		log.Printf("Dropping oversize UDP write")
		return len(b), nil
	}
	return p.Conn.Write(b)
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic [net.PacketConn] of UDP packets.  The remote
// addresses of these packets are not meaningful.
//
// `str` is optional, and indicates datagram support if non-nil.
//
// When the PacketConn is closed, the request and response streams will be closed.
func ProxiedPacketConn(str DatagramSendReceiver, req io.WriteCloser, rsp io.ReadCloser, laddr, raddr net.Addr) net.PacketConn {
	left, right := net.Pipe()

	go func() {
		forwardUDP(str, req, rsp, right)
		req.Close()
		if str != nil {
			str.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	return packetConnWrapper{Conn: left, local: laddr, remote: raddr}
}

package masque

import (
	"io"
	"net"
)

// packetConnWrapper converts a generic (connected) net.Conn
// into a PacketConn that can only be used for a single
// destination.
type packetConnWrapper struct {
	net.Conn
}

func (p packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p packetConnWrapper) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic PacketConn of UDP packets.  The remote addresses
// of these packets are not meaningful.  The caller can terminate the connection
// by closing the input stream.  If `rspStream` is an HTTP/3 stream, and
// `enableDatagrams` is true, then datagrams will be used instead of capsules if
// they can be negotiated.
//
// When the PacketConn is closed, the response stream will be closed.  Closing happens
// at the reader to reflect that the application layer is responsible for preventing
// data loss at closing.
func ProxiedPacketConn(reqStream io.Writer, rspStream io.ReadCloser, enableDatagrams bool) net.PacketConn {
	left, right := net.Pipe()

	go func() {
		forwardUDP(reqStream, rspStream, right, enableDatagrams)
		rspStream.Close()
	}()
	return packetConnWrapper{left}
}

package masque

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type proxiedConn struct {
	str        http3.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.PacketConn = &proxiedConn{}

func (c *proxiedConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	data, err := c.str.ReceiveDatagram(context.Background())
	// TODO: special case context cancellation errors, replace them with timeout errors
	if err != nil {
		return 0, nil, err
	}
	// If b is too small, additional bytes are discarded.
	// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
	n = copy(b, data)
	return n, c.remoteAddr, nil
}

func (c *proxiedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// A CONNECT-UDP connection mirrors a connected UDP socket.
	if addr != c.remoteAddr {
		return 0, fmt.Errorf("unexpected remote address: %s, expected %s", addr, c.remoteAddr)
	}
	return len(p), c.str.SendDatagram(p)
}

func (c *proxiedConn) Close() error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *proxiedConn) SetDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConn) SetWriteDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

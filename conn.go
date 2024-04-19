package masque

import (
	"net"
	"time"
)

type proxiedConnection struct {
}

func (c *proxiedConnection) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) Close() error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) LocalAddr() net.Addr {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) SetDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) SetReadDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

func (c *proxiedConnection) SetWriteDeadline(t time.Time) error {
	// TODO implement me
	panic("implement me")
}

var _ net.PacketConn = &proxiedConnection{}

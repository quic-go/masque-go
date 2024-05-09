package masque

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ net.Addr }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.Addr.String() }

var _ net.Addr = &masqueAddr{}

type proxiedConn struct {
	str        http3.Stream
	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}
}

var _ net.PacketConn = &proxiedConn{}

func newProxiedConn(str http3.Stream, local, remote net.Addr) *proxiedConn {
	c := &proxiedConn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		readDone:   make(chan struct{}),
	}
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != io.EOF && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

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
	c.closed.Store(true)
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	<-c.readDone
	return err
}

func (c *proxiedConn) LocalAddr() net.Addr {
	return &masqueAddr{c.localAddr}
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

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		log.Printf("skipping capsule of type %d", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}

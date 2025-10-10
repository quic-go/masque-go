package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

type proxiedConn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &proxiedConn{}

func newProxiedConn(str http3Stream, local, remote net.Addr) *proxiedConn {
	c := &proxiedConn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		readDone:   make(chan struct{}),
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
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
start:
	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()
	data, err := c.str.ReceiveDatagram(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			return 0, nil, err
		}
		// The context is cancelled asynchronously (in a Go routine spawned from time.AfterFunc).
		// We need to check if a new deadline has already been set.
		c.deadlineMx.Lock()
		restart := time.Now().Before(c.deadline)
		c.deadlineMx.Unlock()
		if restart {
			goto start
		}
		return 0, nil, os.ErrDeadlineExceeded
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, nil, fmt.Errorf("masque: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of UDP payloads.
		goto start
	}
	// If b is too small, additional bytes are discarded.
	// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
	return copy(b, data[n:]), c.remoteAddr, nil
}

// WriteTo sends a UDP datagram to the target.
// The net.Addr parameter is ignored.
func (c *proxiedConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	data := make([]byte, 0, len(contextIDZero)+len(p))
	data = append(data, contextIDZero...)
	data = append(data, p...)
	return len(p), c.str.SendDatagram(data)
}

func (c *proxiedConn) Close() error {
	c.closed.Store(true)
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	<-c.readDone
	c.readCtxCancel()
	c.deadlineMx.Lock()
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
	}
	c.deadlineMx.Unlock()
	return err
}

func (c *proxiedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *proxiedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *proxiedConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	c.deadlineMx.Lock()
	defer c.deadlineMx.Unlock()

	oldDeadline := c.deadline
	c.deadline = t
	now := time.Now()
	// Stop the timer.
	if t.IsZero() {
		if c.readDeadlineTimer != nil && !c.readDeadlineTimer.Stop() {
			<-c.readDeadlineTimer.C
		}

		return nil
	}
	// If the deadline already expired, cancel immediately.
	if !t.After(now) {
		c.readCtxCancel()
		return nil
	}
	deadline := t.Sub(now)
	// if we already have a timer, reset it
	if c.readDeadlineTimer != nil {
		// if that timer expired, create a new one
		if now.Before(oldDeadline) {
			c.readCtxCancel() // the old context might already have been cancelled, but that's not guaranteed
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
		c.readDeadlineTimer.Reset(deadline)
	} else { // this is the first time the timer is set
		c.readDeadlineTimer = time.AfterFunc(deadline, func() {
			c.deadlineMx.Lock()
			defer c.deadlineMx.Unlock()
			if !c.deadline.IsZero() && c.deadline.Before(time.Now()) {
				c.readCtxCancel()
			}
		})
	}
	return nil
}

func (c *proxiedConn) SetWriteDeadline(time.Time) error {
	// TODO(#22): This is currently blocked on a change in quic-go's API.
	return nil
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

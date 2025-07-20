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

type masqueAddr struct{ net.Addr }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.Addr.String() }

var _ net.Addr = &masqueAddr{}

type proxiedConn struct {
	str        http3.Stream
	localAddr  net.Addr
	remoteAddr net.Addr

	isBound          bool
	compressionTable *compressionTable

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &proxiedConn{}

func newProxiedConn(str http3.Stream, local net.Addr, isBound bool) *proxiedConn {
	c := &proxiedConn{
		str:       str,
		localAddr: local,
		isBound:   isBound,
		readDone:  make(chan struct{}),
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != io.EOF && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()

	if isBound {
		fmt.Printf("new compression table\n")
		c.compressionTable = newCompressionTable(true)

		// TODO: The client automatically enables uncompressed datagrams.
		// Figure out what API can be exposed for this.
		contextID, err := c.compressionTable.newUncompressedAssignment()
		if err != nil {
			panic(err)
		}

		log.Printf("client: assigned context ID %d to uncompressed datagrams", contextID)

		capsule := compressionAssignCapsule{
			ContextID: contextID,
			Addr:      nil,
		}
		capsuleData, err := capsule.Marshal()
		if err != nil {
			panic(err)
		}
		err = http3.WriteCapsule(quicvarint.NewWriter(c.str), compressionAsignCapsuleType, capsuleData)
		if err != nil {
			panic(err)
		}

		// TODO: Wait until proxy acknowledged assignment.
	}

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

	if !c.isBound {
		if contextID != 0 {
			// Drop this datagram. We currently only support proxying of UDP payloads.
			goto start
		}
		// If b is too small, additional bytes are discarded.
		// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
		return copy(b, data[n:]), c.remoteAddr, nil
	} else {
		addr, found := c.compressionTable.lookupContextID(contextID)
		if !found {
			log.Printf("client: dropping incoming datagram because no context ID is assigned to %s", addr.String())
			goto start
		}

		log.Printf("client: received datagram (context ID: %d, isCompressed: %t)", contextID, addr != nil)

		if addr != nil {
			return copy(b, data[n:]), addr, nil
		} else {
			dg := uncompressedDatagram{}
			err := dg.Unmarshal(data[n:])
			if err != nil {
				return 0, nil, fmt.Errorf("client: malformed datagram: %w", err)
			}

			// If b is too small, additional bytes are discarded.
			// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
			return copy(b, dg.Data), dg.Addr, nil
		}
	}
}

// WriteTo sends a UDP datagram to the target.
// The net.Addr parameter is ignored for unbound connections.
func (c *proxiedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.isBound {
		data := make([]byte, 0, len(contextIDZero)+len(p))
		data = append(data, contextIDZero...)
		data = append(data, p...)
		return len(p), c.str.SendDatagram(data)
	} else {
		contextID, isCompressed, found := c.compressionTable.lookupAddr(addr.(*net.UDPAddr))
		if !found {
			return 0, fmt.Errorf("masque: dropping outgoing datagram because no context ID is assigned to %s", addr.String())
		}

		var data []byte
		if !isCompressed {
			dg := uncompressedDatagram{
				Addr: addr.(*net.UDPAddr),
				Data: p,
			}
			data, err = dg.Marshal()
			if err != nil {
				return 0, err
			}
		}

		data = prependContextID(data, contextID)

		log.Printf("client: sending datagram (context ID: %d, isCompressed: %t)\n", contextID, isCompressed)
		err := c.str.SendDatagram(data)
		if err != nil {
			return 0, err
		}

		return len(p), nil
	}
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
	return &masqueAddr{c.localAddr}
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

		// TODO: Currently all capsules are skipped. Properly handle them.
		log.Printf("client: skipping capsule of type 0x%X", ct)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return err
		}
	}
}

package masque

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const datagramCapsuleType = 0x00

// DatagramSender sends HTTP Datagrams and can be closed.
type DatagramSender interface {
	SendDatagram(b []byte) error
	io.Closer
}

// DatagramReceiver receives HTTP Datagrams.
type DatagramReceiver interface {
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}

// DatagramReceiverCanceller is a DatagramReceiver whose read side can be cancelled.
type DatagramReceiverCanceller interface {
	DatagramReceiver
	CancelRead(quic.StreamErrorCode)
}

// DatagramSendReceiver is the common datagram interface of
// [http3.Stream] and [http3.RequestStream].
type DatagramSendReceiver interface {
	DatagramSender
	DatagramReceiverCanceller
}

var _ DatagramSendReceiver = &http3.Stream{}
var _ DatagramSendReceiver = &http3.RequestStream{}

func isCleanShutdownError(err error) bool {
	var qErr *quic.StreamError
	if errors.As(err, &qErr) && qErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeConnectError) && !qErr.Remote {
		return true
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}

	var h3Err *http3.Error
	if errors.As(err, &h3Err) && h3Err.ErrorCode == 0x0 && !h3Err.Remote {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0x0 {
		return true
	}

	return false
}

// `r`, `w`, and `conn` are required.
// `str` indicates Datagram support if non-nil.
func forwardUDP(str DatagramSendReceiver, w io.WriteCloser, r io.ReadCloser, conn net.Conn) error {
	var wg sync.WaitGroup
	var readErr, sendErr, writeErr error
	if str != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := proxyConnReceive(conn, str); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying %s to datagrams stopped: %v", conn.RemoteAddr(), err)
			}
			r.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}()
		go func() {
			defer wg.Done()
			if err := proxyConnSend(conn, http3DatagramReceiver{str}); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying datagrams to %s failed: %v", conn.RemoteAddr(), err)
				sendErr = err
			}
			r.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			conn.Close()
		}()
		// discard all capsules sent on the request stream
		if err := skipCapsules(r); err != nil && !isCleanShutdownError(err) && !errors.Is(err, io.EOF) {
			log.Printf("reading from request stream failed: %v", err)
			readErr = err
		}
	} else {
		wg.Go(func() {
			if err := udpToCapsules(w, conn); err != nil && !isCleanShutdownError(err) {
				log.Printf("writing to HTTP stream failed: %v", err)
				writeErr = err
			}
			r.Close()
		})

		// The remote peer can always choose to send capsules.
		if err := capsulesToUDP(conn, r); err != nil && !isCleanShutdownError(err) {
			log.Printf("reading from HTTP stream failed: %v", err)
			readErr = err
		}
		w.Close()
	}

	conn.Close()
	wg.Wait()
	if readErr != nil {
		return readErr
	}
	if sendErr != nil {
		return sendErr
	}
	return writeErr
}

func capsulesToUDP(conn io.Writer, body io.Reader) error {
	return proxyConnSend(conn, newCapsuleReceiver(body))
}

func udpToCapsules(w io.WriteCloser, conn io.Reader) error {
	str := newCapsuleSender(w)
	return proxyConnReceive(conn, str)
}

var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPPayloadSize)
		return &buf
	},
}

type packetConnWrapper struct {
	net.Conn
	req       io.Closer
	rsp       io.Closer
	closeOnce sync.Once
	closeErr  error
	// done is closed after forwardUDP returns and readErr has been written.
	// Because net.Pipe does not support CloseWithError, forwardUDP closes the
	// pipe before returning; Read waits on done upon seeing io.EOF so it can
	// safely observe readErr without racing against the forwarding goroutine.
	done       chan struct{}
	readErr    error
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.PacketConn = (*packetConnWrapper)(nil)

func (p *packetConnWrapper) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

func (p *packetConnWrapper) LocalAddr() net.Addr {
	return p.localAddr
}

func (p *packetConnWrapper) RemoteAddr() net.Addr {
	return p.remoteAddr
}

func (p *packetConnWrapper) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

func (p *packetConnWrapper) Read(b []byte) (int, error) {
	var n int
	var err error
	if len(b) >= maxUDPPayloadSize {
		n, err = p.Conn.Read(b)
	} else {
		buf := udpBufPool.Get().(*[]byte)
		n, err = p.Conn.Read(*buf)
		n = copy(b, (*buf)[:n])
		udpBufPool.Put(buf)
	}
	if errors.Is(err, io.EOF) {
		// net.Pipe reports io.EOF when the peer end closes, even if forwardUDP
		// terminated due to a capsule parse or transport error. Wait for
		// forwardUDP to store readErr and surface that error if present.
		<-p.done
		if p.readErr != nil {
			return 0, p.readErr
		}
	}
	return n, err
}

func (p *packetConnWrapper) Write(b []byte) (int, error) {
	if len(b) > maxUDPPayloadSize {
		log.Printf("dropping oversize UDP write (%d > %d)", len(b), maxUDPPayloadSize)
		return len(b), nil
	}
	return p.Conn.Write(b)
}

func (p *packetConnWrapper) Close() error {
	p.closeOnce.Do(func() {
		var errs []error
		if err := p.Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		if p.req != nil {
			if err := p.req.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if p.rsp != nil {
			if err := p.rsp.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic [net.PacketConn] of UDP packets.
//
// `str` is optional, and indicates datagram support if non-nil.
// When the PacketConn is closed, the request and response streams will be closed.
func ProxiedPacketConn(str DatagramSendReceiver, req io.WriteCloser, rsp io.ReadCloser, laddr, raddr net.Addr) net.PacketConn {
	left, right := net.Pipe()
	reqCloser := &sharedCloser{c: req}
	reqWrapped := struct {
		io.Writer
		io.Closer
	}{req, reqCloser}
	wrapper := &packetConnWrapper{
		Conn:       left,
		req:        reqCloser,
		rsp:        rsp,
		done:       make(chan struct{}),
		localAddr:  laddr,
		remoteAddr: raddr,
	}

	go func() {
		wrapper.readErr = forwardUDP(str, reqWrapped, rsp, right)
		close(wrapper.done)
		reqCloser.Close()
		if str != nil {
			str.Close()
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	return wrapper
}

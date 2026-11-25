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
	"github.com/quic-go/quic-go/quicvarint"
)

const datagramCapsuleType = 0x00

type DatagramSender interface {
	SendDatagram(b []byte) error
	io.Closer
}

type DatagramReceiver interface {
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	CancelRead(quic.StreamErrorCode)
}

// DatagramSendReceiver is the common datagram interface of
// [http3.Stream] and [http3.RequestStream].
type DatagramSendReceiver interface {
	DatagramSender
	DatagramReceiver
}

var _ DatagramSendReceiver = &http3.Stream{}
var _ DatagramSendReceiver = &http3.RequestStream{}

func isCleanShutdownError(err error) bool {
	var qErr *quic.StreamError
	if errors.As(err, &qErr) && qErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeConnectError) && !qErr.Remote {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err.Error() == "use of closed network connection" {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
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
func forwardUDP(str DatagramSendReceiver, w io.Writer, r io.ReadCloser, conn net.Conn) {
	var wg sync.WaitGroup
	if str != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := proxyConnReceive(conn, str); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying %s to datagrams stopped: %v", conn.RemoteAddr(), err)
			}
			r.Close()
		}()
		go func() {
			defer wg.Done()
			if err := proxyConnSend(conn, str); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying datagrams to %s failed: %v", conn.RemoteAddr(), err)
			}
		}()
		// discard all capsules sent on the request stream
		if err := skipCapsules(r); err != nil && !isCleanShutdownError(err) && !errors.Is(err, io.EOF) {
			log.Printf("reading from request stream failed: %v", err)
		}
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := udpToCapsules(w, conn); err != nil && !isCleanShutdownError(err) {
				log.Printf("writing to HTTP stream failed: %v", err)
			}
			r.Close()
		}()

		// The remote peer can always choose to send capsules.
		if err := capsulesToUDP(conn, r); err != nil && !isCleanShutdownError(err) {
			log.Printf("reading from HTTP stream failed: %v", err)
		}
	}

	conn.Close()
	wg.Wait()
}

func capsulesToUDP(conn io.Writer, body io.Reader) error {
	parser := http3.NewCapsuleParser(body)
	b := make([]byte, maxUDPPayloadSize+1)
	for {
		capsuleType, content, err := parser.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if capsuleType != datagramCapsuleType {
			log.Printf("skipping unknown capsule type %d", capsuleType)
			if _, err := io.Copy(io.Discard, content); err != nil {
				return err
			}
			continue
		}
		n, err := readAll(content, b)
		if n > maxUDPPayloadSize {
			remainder, err := io.Copy(io.Discard, content)
			if err != nil {
				return err
			}
			log.Printf("skipped datagram capsule larger than MTU (%d > %d)", int64(n)+remainder, maxUDPPayloadSize)
			continue
		}
		if err != nil {
			return err
		}
		if _, err := conn.Write(b[:n]); err != nil {
			return err
		}
	}
}

func readAll(r io.Reader, b []byte) (int, error) {
	blen := 0
	for blen < len(b) {
		n, err := r.Read(b[blen:])
		blen += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return blen, nil
			}
			return blen, err
		}
	}
	return blen, io.ErrShortBuffer
}

func udpToCapsules(w io.Writer, conn io.Reader) error {
	qw := quicvarint.NewWriter(w)
	b := make([]byte, maxUDPPayloadSize+1)
	for {
		n, err := conn.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU (%d > %d)", n, maxUDPPayloadSize)
			continue
		}
		if err := http3.WriteCapsule(qw, datagramCapsuleType, b[:n]); err != nil {
			return err
		}
	}
}

var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPPayloadSize)
		return &buf
	},
}

type packetConnWrapper struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.PacketConn = packetConnWrapper{}

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
	buf := udpBufPool.Get().(*[]byte)
	n, err := p.Conn.Read(*buf)
	n = copy(b, (*buf)[:n])
	udpBufPool.Put(buf)
	return n, err
}

func (p packetConnWrapper) Write(b []byte) (int, error) {
	if len(b) > maxUDPPayloadSize {
		log.Printf("dropping oversize UDP write (%d > %d)", len(b), maxUDPPayloadSize)
		return len(b), nil
	}
	return p.Conn.Write(b)
}

// ProxiedPacketConn converts an HTTP request and response stream, speaking
// connect-udp, into a synthetic [net.PacketConn] of UDP packets.
//
// `str` is optional, and indicates datagram support if non-nil.
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
	return packetConnWrapper{Conn: left, localAddr: laddr, remoteAddr: raddr}
}

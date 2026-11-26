package masque

import (
	"context"
	"io"
	"log"
	"sync"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// datagramReader reads the payload of a single HTTP Datagram.
// Implementations (such as [http3.CapsuleReader]) allow inspecting the Context ID
// and remaining payload length before buffering the body.
type datagramReader interface {
	quicvarint.Reader
	Remaining() int64
	Discard() error
}

var _ datagramReader = http3.CapsuleReader{}

type datagramStreamReceiver interface {
	NextDatagram(ctx context.Context) (datagramReader, error)
}

type bytesDatagramReader struct {
	b []byte
}

func (r *bytesDatagramReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func (r *bytesDatagramReader) ReadByte() (byte, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

func (r *bytesDatagramReader) Remaining() int64 { return int64(len(r.b)) }
func (r *bytesDatagramReader) Discard() error   { r.b = nil; return nil }

type http3DatagramReceiver struct {
	str DatagramReceiver
}

func (r http3DatagramReceiver) NextDatagram(ctx context.Context) (datagramReader, error) {
	data, err := r.str.ReceiveDatagram(ctx)
	if err != nil {
		return nil, err
	}
	return &bytesDatagramReader{b: data}, nil
}

var capsuleWritePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 16+len(contextIDZero)+maxUDPPayloadSize)
		return &b
	},
}

type capsuleSender struct {
	w io.WriteCloser
}

func newCapsuleSender(w io.WriteCloser) DatagramSender {
	return &capsuleSender{w: w}
}

func (s *capsuleSender) Close() error {
	return s.w.Close()
}

func (s *capsuleSender) SendDatagram(b []byte) error {
	bufPtr := capsuleWritePool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	buf = quicvarint.Append(buf, datagramCapsuleType)
	buf = quicvarint.Append(buf, uint64(len(b)))
	buf = append(buf, b...)
	_, err := s.w.Write(buf)
	*bufPtr = buf
	capsuleWritePool.Put(bufPtr)
	return err
}

type capsuleReceiver struct {
	parser *http3.CapsuleParser
}

// NextDatagram returns a reader for the next received DATAGRAM capsule,
// skipping any unknown capsule types per RFC 9297 Section 3.2.
func (r *capsuleReceiver) NextDatagram(_ context.Context) (datagramReader, error) {
	for {
		capsuleType, content, err := r.parser.Next()
		if err != nil {
			return nil, err
		}
		if capsuleType != datagramCapsuleType {
			log.Printf("skipping unknown capsule type %d", capsuleType)
			if err := content.Discard(); err != nil {
				return nil, err
			}
			continue
		}
		return content, nil
	}
}

func newCapsuleReceiver(r io.Reader) *capsuleReceiver {
	return &capsuleReceiver{
		parser: http3.NewCapsuleParser(r),
	}
}

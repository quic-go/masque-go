package masque_test

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/stretchr/testify/require"
)

func TestUDPToCapsule(t *testing.T) {
	payload := []byte("upstream")
	expectedHeader := []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 9 /* Context ID 0 */, 0x00}
	expected := append(expectedHeader, payload...)
	t.Run("simple", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = nil
	expected = []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 1 /* Context ID 0 */, 0x00}
	t.Run("empty payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1500)
	expected = append([]byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 0x45, 0xdd /* Context ID 0 */, 0x00}, payload...)
	t.Run("max size payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1501)
	expected = []byte{}
	t.Run("oversize payload (1501)", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })
}

func testUDPToCapsule(t *testing.T, payload, expected []byte) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	readDone := make(chan struct{})
	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn.WriteTo(payload, addr)
		require.NoError(t, err)
		<-readDone
		require.NoError(t, conn.Close())
		require.NoError(t, rspWriter.Close())
	}()

	received := make([]byte, len(expected))
	_, err := io.ReadFull(reqReader, received)
	close(readDone)
	require.NoError(t, err)
	require.Equal(t, expected, received)

	rest, err := io.ReadAll(reqReader)
	require.NoError(t, err)
	require.Empty(t, rest)
}

func TestCapsulesToUDP(t *testing.T) {
	stream := []byte{
		// DATAGRAM capsule type varint (0x00)
		0x00,
		// Payload length varint (11)
		11,
		// Context ID 0
		0x00,
		// Payload ("downstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := [][]byte{[]byte("downstream")}
	t.Run("simple", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 1, 0x00}
	expected = [][]byte{{}}
	t.Run("empty payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 2, 0x00, 1, 0x00, 2, 0x00, 2, 0x00, 2, 0x00, 3}
	expected = [][]byte{{1}, {2}, {3}}
	t.Run("received in order", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdd, 0x00}, make([]byte, 1500)...)
	expected = [][]byte{make([]byte, 1500)}
	t.Run("max payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xde, 0x00}, make([]byte, 1501)...)
	expected = [][]byte{} // Dropped
	t.Run("oversize payload (1501)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{
		// DATAGRAM capsule with non-zero Context ID (0x01) -> skipped
		0x00, 5, 0x01, 's', 'k', 'i', 'p',
		// Followed by valid DATAGRAM capsule with Context ID 0 -> delivered
		0x00, 5, 0x00, 'k', 'e', 'e', 'p',
	}
	expected = [][]byte{[]byte("keep")}
	t.Run("skip non-zero context ID", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{
		// Unknown capsule type (0x17) -> skipped
		0x17, 4, 's', 'k', 'i', 'p',
		// Followed by valid DATAGRAM capsule with Context ID 0 -> delivered
		0x00, 5, 0x00, 'k', 'e', 'e', 'p',
	}
	expected = [][]byte{[]byte("keep")}
	t.Run("skip unknown capsule type", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	// Greatly oversize DATAGRAM capsule (10 * 1500 = 15000 bytes payload + 1 byte Context ID = 15001 bytes;
	// 4-byte QUIC varint length: 0x80003a99) -> skipped without corrupting the next capsule
	stream = append([]byte{0x00, 0x80, 0x00, 0x3a, 0x99, 0x00}, make([]byte, 10*1500)...)
	stream = append(stream, 0x00, 5, 0x00, 'k', 'e', 'e', 'p')
	expected = [][]byte{[]byte("keep")}
	t.Run("skip greatly oversize payload (10x MTU)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })
}

func TestCapsulesToUDPErrors(t *testing.T) {
	tests := []struct {
		name   string
		stream []byte
	}{
		{
			name:   "empty DATAGRAM capsule missing Context ID",
			stream: []byte{0x00, 0x00},
		},
		{
			name:   "truncated DATAGRAM capsule",
			stream: []byte{0x00, 0x05, 0x00, 'a'},
		},
		{
			name: "Context ID 0 payload > 65527 bytes",
			// Length = 1 (Context ID) + 65528 = 65529 (0x0000fff9 -> 0x8000fff9)
			stream: []byte{0x00, 0x80, 0x00, 0xff, 0xf9, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rspReader, rspWriter := io.Pipe()
			_, reqWriter := io.Pipe()

			conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)
			defer conn.Close()

			go func() {
				_, _ = rspWriter.Write(tc.stream)
				_ = rspWriter.Close()
			}()

			_, _, err := conn.ReadFrom(make([]byte, 1500))
			require.Error(t, err)
			require.NotErrorIs(t, err, io.EOF)
		})
	}
}

func testCapsulesToUDP(t *testing.T, stream []byte, expected [][]byte) {
	rspReader, rspWriter := io.Pipe()
	_, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	go func() {
		_, err := rspWriter.Write(stream)
		require.NoError(t, err)
		require.NoError(t, rspWriter.Close())
	}()

	for _, payload := range expected {
		buf := make([]byte, len(payload)+1)
		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf[:n])
	}

	n, _, err := conn.ReadFrom(make([]byte, 1))
	require.Equal(t, io.EOF, err)
	require.Equal(t, 0, n)

	err = conn.Close()
	require.NoError(t, err)
}

func TestShortReadBuffers(t *testing.T) {
	datagram := []byte{
		0x00, // type
		11,   // length
		0x00, // context ID
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := []byte("downstream")

	var buf bytes.Buffer
	buf.Write(datagram)
	buf.Write(datagram)

	rspReader, rspWriter := io.Pipe()
	_, reqWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	go func() {
		_, _ = rspWriter.Write(buf.Bytes())
		_ = rspWriter.Close()
	}()

	// Short buffer
	shortBuf := make([]byte, 10)
	n, _, err := conn.ReadFrom(shortBuf)
	require.NoError(t, err)
	require.Equal(t, expected, shortBuf[:n])

	// Truncated buffer
	veryShortBuf := make([]byte, 4)
	n, _, err = conn.ReadFrom(veryShortBuf)
	require.NoError(t, err)
	require.Equal(t, expected[:4], veryShortBuf[:n])

	_ = conn.Close()
}

type countCloser struct {
	io.ReadWriteCloser
	closes atomic.Int32
}

func (c *countCloser) Close() error {
	c.closes.Add(1)
	return c.ReadWriteCloser.Close()
}

func TestProxiedPacketConnCloseUnblocksStalledStreamsAndIsIdempotent(t *testing.T) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()
	defer rspWriter.Close()
	defer reqReader.Close()

	req := &countCloser{ReadWriteCloser: struct {
		io.Reader
		io.Writer
		io.Closer
	}{Writer: reqWriter, Closer: reqWriter}}
	rsp := &countCloser{ReadWriteCloser: struct {
		io.Reader
		io.Writer
		io.Closer
	}{Reader: rspReader, Closer: rspReader}}

	conn := masque.ProxiedPacketConn(nil, req, rsp, nil, nil)

	// Write a packet so udpToCapsules blocks in req.Write (nobody is reading reqReader),
	// while capsulesToUDP blocks in rsp.Read (nobody is writing to rspWriter).
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("stalled"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678})
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("WriteTo did not hand off to forwarding goroutine")
	}

	// Give udpToCapsules a moment to block in req.Write.
	time.Sleep(20 * time.Millisecond)

	// Close must unblock both req.Write and rsp.Read and be idempotent.
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())

	// Both streams were closed by packetConnWrapper.Close() (and req again by ProxiedPacketConn exit).
	require.GreaterOrEqual(t, req.closes.Load(), int32(1))
	require.GreaterOrEqual(t, rsp.closes.Load(), int32(1))

	// Verify reqReader and rspWriter now see closed pipes immediately.
	_, err := reqReader.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	_, err = rspWriter.Write([]byte{0})
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

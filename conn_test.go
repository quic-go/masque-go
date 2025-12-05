package masque_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestUDPToDatagram(t *testing.T) {
	header := [1]byte{0x00} // UDP Context ID

	payload := []byte("upstream")
	expected := append(header[:], payload...)
	t.Run("simple", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })

	payload = nil
	expected = header[:]
	t.Run("empty payload", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })

	payload = make([]byte, 1500)
	expected = append(header[:], payload...)
	t.Run("max size payload", func(t *testing.T) { testUDPToDatagram(t, payload, expected) })
}

func testUDPToDatagram(t *testing.T, payload, expected []byte) {
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent: make(chan []byte),
	}

	unusedReader, _ := io.Pipe()

	conn := masque.ProxiedPacketConn(fakeStream, unusedReader, nil, nil)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	// Write upstream data
	_, err := conn.WriteTo(payload, addr)
	require.NoError(t, err)

	// Check that upstream datagram was sent correctly
	datagram := <-fakeStream.datagramsSent
	require.Equal(t, expected, datagram)

	// Clean up
	err = conn.Close()
	require.NoError(t, err)
}

// fakeH3Stream implements DatagramSendReceiver for testing
type fakeH3Stream struct {
	datagramsSent      chan []byte
	datagramsToReceive [][]byte
}

func (f *fakeH3Stream) SendDatagram(b []byte) error {
	f.datagramsSent <- b
	return nil
}

func (f *fakeH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if len(f.datagramsToReceive) == 0 {
		return nil, io.EOF
	}
	datagram := f.datagramsToReceive[0]
	f.datagramsToReceive = f.datagramsToReceive[1:]
	return datagram, nil
}

func (f *fakeH3Stream) Close() error {
	close(f.datagramsSent)
	return nil
}

func (f *fakeH3Stream) CancelRead(code quic.StreamErrorCode) {}

func TestDatagramToUDP(t *testing.T) {
	datagram := []byte{
		// DATAGRAM context ID varint (0x00)
		0x00,
		// Payload ("upstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := []byte("downstream")
	t.Run("simple", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })

	datagram = []byte{0x00}
	expected = []byte{}
	t.Run("empty payload", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })

	datagram = append([]byte{0x00}, make([]byte, 1500)...)
	expected = make([]byte, 1500)
	t.Run("max payload", func(t *testing.T) { testDatagramToUDP(t, datagram, expected) })
}

func testDatagramToUDP(t *testing.T, datagram, expected []byte) {
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{datagram},
	}

	unusedReader, _ := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedReader, nil, nil)

	// Check that the datagram was converted to UDP correctly
	buf := make([]byte, 10*1024)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, expected, buf[:n])

	// Clean up
	err = conn.Close()
	require.NoError(t, err)
}

func TestOversizeDatagramIsDropped(t *testing.T) {
	oversizeDatagram := append([]byte{0x00}, make([]byte, 1501)...)
	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{oversizeDatagram},
	}

	unusedReader, _ := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedReader, nil, nil)

	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))

	// Check that no UDP packets are emitted.
	buf := make([]byte, 10*1024)
	n, _, err := conn.ReadFrom(buf)
	require.Error(t, err)
	require.Equal(t, 0, n)

	require.NoError(t, conn.Close())
}

func TestOversizePacketIsDropped(t *testing.T) {
	payload := make([]byte, 1501)

	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent: make(chan []byte),
	}

	unusedReader, _ := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedReader, nil, nil)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	go func() {
		// Write oversized packet
		_, err := conn.WriteTo(payload, addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}()

	// Check that the datagram channel was closed without sending any
	// datagrams
	_, open := <-fakeStream.datagramsSent
	require.False(t, open)
}

// ProxiedPacketConn has special logic for when the read buffer is smaller
// than the MTU, and implicitly also when the read buffer is smaller than
// the received packet payload.  This test checks both of those cases.
func TestShortReadBuffers(t *testing.T) {
	datagram := []byte{
		// DATAGRAM context ID varint (0x00)
		0x00,
		// Payload ("upstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := []byte("downstream")

	// Create a fake httpStreamer implementation
	fakeStream := &fakeH3Stream{
		datagramsSent:      make(chan []byte),
		datagramsToReceive: [][]byte{datagram, datagram},
	}

	unusedReader, unusedWriter := io.Pipe()
	conn := masque.ProxiedPacketConn(fakeStream, unusedReader, nil, nil)

	// Try a read using a short buffer of exactly the right length.
	// Applications that use fixed-size UDP packets might do this.
	shortBuf := make([]byte, 10)
	n, _, err := conn.ReadFrom(shortBuf)
	require.NoError(t, err)
	require.Equal(t, expected, shortBuf[:n])

	// Try a read using a buffer that is too short.  The data should be
	// truncated.
	veryShortBuf := make([]byte, 4)
	n, _, err = conn.ReadFrom(veryShortBuf)
	require.NoError(t, err)
	require.Equal(t, expected[:4], veryShortBuf[:n])

	// Remote side closed the incoming HTTP stream.
	unusedWriter.Close()

	// Confirm that the remainder of the datagram is not returned by
	// a subsequent read call.
	bigBuf := make([]byte, 10*1024)
	n, _, err = conn.ReadFrom(bigBuf)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)

	t.Logf("bemasc 2")

	// Clean up
	err = conn.Close()
	require.NoError(t, err)

}

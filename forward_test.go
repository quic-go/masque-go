package masque_test

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/stretchr/testify/require"
)

func TestUDPToCapsule(t *testing.T) {
	payload := []byte("upstream")
	expectedHeader := []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 8}
	expected := append(expectedHeader, payload...)
	t.Run("simple", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = nil
	expected = []byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 0}
	t.Run("empty payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1500)
	expected = append([]byte{ /* DATAGRAM capsule type */ 0x00 /* varint length */, 0x45, 0xdc}, payload...)
	t.Run("max size payload", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })

	payload = make([]byte, 1501)
	expected = []byte{}
	t.Run("oversize payload (1501)", func(t *testing.T) { testUDPToCapsule(t, payload, expected) })
}

func testUDPToCapsule(t *testing.T, payload, expected []byte) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(nil, reqWriter, rspReader, nil, nil)

	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn.WriteTo(payload, addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		require.NoError(t, rspWriter.Close())
	}()

	received, err := io.ReadAll(reqReader)
	require.NoError(t, err)
	require.Equal(t, expected, received)
}

func TestCapsulesToUDP(t *testing.T) {
	stream := []byte{
		// DATAGRAM capsule type varint (0x00)
		0x00,
		// Payload length varint (10)
		10,
		// Payload ("downstream")
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}
	expected := [][]byte{[]byte("downstream")}
	t.Run("simple", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 0}
	expected = [][]byte{{}}
	t.Run("empty payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = []byte{0x00, 1, 1, 0x00, 1, 2, 0x00, 1, 3}
	expected = [][]byte{{1}, {2}, {3}}
	t.Run("received in order", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdc}, make([]byte, 1500)...)
	expected = [][]byte{make([]byte, 1500)}
	t.Run("max payload", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })

	stream = append([]byte{0x00, 0x45, 0xdd}, make([]byte, 1501)...)
	expected = [][]byte{} // Dropped
	t.Run("oversize payload (1501)", func(t *testing.T) { testCapsulesToUDP(t, stream, expected) })
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
		10,   // length
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

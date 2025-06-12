package masque_test

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestUDPCapsules(t *testing.T) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn := masque.ProxiedPacketConn(reqWriter, rspReader, false) // enableDatagrams=false for capsule mode

	go func() {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
		_, err := conn.WriteTo([]byte("upstream"), addr)
		require.NoError(t, err)
	}()

	go func() {
		downstream := []byte{
			// DATAGRAM capsule type varint (0x00)
			0x00,
			// Payload length varint (10)
			10,
			// Payload ("downstream")
			'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
		}

		_, err := rspWriter.Write(downstream)
		require.NoError(t, err)
	}()

	expectedUpstream := []byte{
		// DATAGRAM capsule type varint (0x00)
		0x00,
		// Payload length varint (8)
		8,
		// Payload ("upstream")
		'u', 'p', 's', 't', 'r', 'e', 'a', 'm',
	}

	receivedUpstream := make([]byte, len(expectedUpstream))
	_, err := io.ReadFull(reqReader, receivedUpstream)
	require.NoError(t, err)
	require.Equal(t, expectedUpstream, receivedUpstream)

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("downstream"), buf[:n])

	err = conn.Close()
	require.NoError(t, err)

	err = reqReader.Close()
	require.NoError(t, err)
}

func TestUDPDatagrams(t *testing.T) {
	// Send a datagram downstream first
	downstream := []byte{
		0x00, // context ID varint (0)
		'd', 'o', 'w', 'n', 's', 't', 'r', 'e', 'a', 'm',
	}

	// Create a fake httpStreamer implementation
	fakeStreamer := &fakeHTTPStreamer{
		datagramsSent: make(chan []byte),
		datagramsToReceive: [][]byte{downstream},
	}

	// Create a fake settings monitor that indicates datagrams are enabled
	receivedSettings := make(chan struct{})
	close(receivedSettings) // Signal that settings have been received
	fakeSettingsMonitor := &fakeH3SettingsMonitor{
		receivedSettings: receivedSettings,
		settings: &http3.Settings{
			EnableExtendedConnect: true,
			EnableDatagrams:       true,
		},
	}

	// Wrap reqWriter to implement the httpStreamer interface
	fakeWriter := &httpStreamerWriter{
		streamer:        fakeStreamer,
		settingsMonitor: fakeSettingsMonitor,
	}

	// No capsules are received on the capsule stream, so we use
	// a fake reader that does nothing until it is closed.
	capsuleStream := &blockReader{
		closed: make(chan struct{}),
	}

	conn := masque.ProxiedPacketConn(fakeWriter, capsuleStream, true) // enableDatagrams=true for datagram mode
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	// Write upstream data
	_, err := conn.WriteTo([]byte("upstream"), addr)
	require.NoError(t, err)

	// Check that upstream datagram was sent correctly
	datagram := <-fakeStreamer.datagramsSent
	expected := []byte{
		0x00, // context ID varint (0)
		'u', 'p', 's', 't', 'r', 'e', 'a', 'm',
	}
	require.Equal(t, expected, datagram)

	// Check that downstream datagram was received correctly
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("downstream"), buf[:n])

	// Clean up
	err = conn.Close()
	require.NoError(t, err)
}

type blockReader struct {
	closed chan struct{}
}

func (r *blockReader) Read(p []byte) (int, error) {
	<-r.closed
	return 0, io.EOF
}

func (r *blockReader) Close() error {
	select {
		case <-r.closed: return nil
		default: close(r.closed)
	}
	return nil
}

// fakeHTTPStreamer implements DatagramSendReceiver for testing
type fakeHTTPStreamer struct {
	datagramsSent chan []byte
	datagramsToReceive [][]byte
}

func (f *fakeHTTPStreamer) SendDatagram(b []byte) error {
	f.datagramsSent <- b
	return nil
}

func (f *fakeHTTPStreamer) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if len(f.datagramsToReceive) == 0 {
		return nil, io.EOF
	}
	datagram := f.datagramsToReceive[0]
	f.datagramsToReceive = f.datagramsToReceive[1:]
	return datagram, nil
}

func (f *fakeHTTPStreamer) Close() error {
	close(f.datagramsSent)
	return nil
}

// fakeH3SettingsMonitor implements H3SettingsMonitor for testing
type fakeH3SettingsMonitor struct {
	receivedSettings chan struct{}
	settings         *http3.Settings
}

func (f *fakeH3SettingsMonitor) ReceivedSettings() <-chan struct{} {
	return f.receivedSettings
}

func (f *fakeH3SettingsMonitor) Settings() *http3.Settings {
	return f.settings
}

// httpStreamerWriter wraps an io.Writer and implements the httpStreamer interface
type httpStreamerWriter struct {
	io.Writer
	streamer        *fakeHTTPStreamer
	settingsMonitor *fakeH3SettingsMonitor
}

func (w *httpStreamerWriter) HTTPStream() masque.DatagramSendReceiver {
	return w.streamer
}

func (w *httpStreamerWriter) Connection() masque.H3SettingsMonitor {
	return w.settingsMonitor
}

func setupTandemUDP() (net.PacketConn, net.PacketConn) {
	rspReader, rspWriter := io.Pipe()
	reqReader, reqWriter := io.Pipe()

	conn1 := masque.ProxiedPacketConn(reqWriter, rspReader, false)
	conn2 := masque.ProxiedPacketConn(rspWriter, reqReader, false)

	return conn1, conn2
}

// Connects two proxied UDP connections back-to-back, and confirms that
// packets flow through and are reconstructed correctly.
func TestUDPConnectionTandem(t *testing.T) {
	run := func(t *testing.T, conn1, conn2 net.PacketConn) {
		input := []byte{1, 2, 3, 4, 5}

		go func() {
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
			_, err := conn1.WriteTo(input, addr)
			require.NoError(t, err)
		} ()

		buf := make([]byte, 1024)
		n, _, err := conn2.ReadFrom(buf)
		require.NoError(t, err)
		output := buf[:n]
		require.Equal(t, input, output)

		conn1.Close()
		conn2.Close()
	}

	conn1, conn2 := setupTandemUDP()
	t.Run("forward", func(t *testing.T) { run(t, conn1, conn2) })
	conn1, conn2 = setupTandemUDP()
	t.Run("reverse", func(t *testing.T) { run(t, conn2, conn1) })
}

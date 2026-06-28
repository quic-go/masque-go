package masque_test

import (
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/stretchr/testify/require"
)

func TestNewClientConnRequiresQUICDatagrams(t *testing.T) {
	conn, _ := newConnPairWithDatagrams(t, false)

	_, err := new(masque.Transport).NewClientConn(conn)
	require.ErrorContains(t, err, "Datagram support")
}

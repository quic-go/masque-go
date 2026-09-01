package masque_test

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestTransportAddsDefaultPort(t *testing.T) {
	req, err := masque.NewRequest(t.Context(), uritemplate.MustNew("https://proxy.example/masque?h={target_host}&p={target_port}"), "target.example:443")
	require.NoError(t, err)

	dialErr := errors.New("dial stopped")
	tr := masque.Transport{
		DialAddr: func(_ context.Context, addr string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			require.Equal(t, "proxy.example:443", addr)
			return nil, dialErr
		},
	}
	_, _, err = tr.Dial(req)
	require.ErrorIs(t, err, dialErr)
}

func TestNewClientConnRequiresQUICDatagrams(t *testing.T) {
	conn, _ := newConnPairWithDatagrams(t, false)

	_, err := new(masque.Transport).NewClientConn(conn)
	require.ErrorContains(t, err, "Datagram support")
}

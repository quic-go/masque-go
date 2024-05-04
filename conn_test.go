package masque

import (
	"bytes"
	"io"
	"log"
	"os"
	"testing"

	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

func TestCapsuleSkipping(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, 1337, []byte("foo")))
	require.NoError(t, http3.WriteCapsule(&buf, 42, []byte("bar")))
	require.ErrorIs(t, skipCapsules(&buf), io.EOF)
}

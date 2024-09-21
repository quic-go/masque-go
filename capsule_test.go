package masque

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestParseAddressAssignCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length

	data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	capsule, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.AssignedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestParseAddressAssignCapsuleInvalid(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 5)              // Invalid IP version (not 4 or 6)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseAddressAssignCapsule(cr)
		require.ErrorContains(t, err, "invalid IP version: 5")
	})

	t.Run("invalid prefix length", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 33) // too long IP Prefix Length
		data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseAddressAssignCapsule(cr)
		require.ErrorContains(t, err, "prefix length 33 exceeds IP address length (32)")
	})

	t.Run("lower bits not covered by prefix length are not all zero", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)                                    // Request ID
		addr1 = append(addr1, 4)                                                 // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // non-zero lower bits
		addr1 = append(addr1, 28)                                                // IP Prefix Length
		data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseAddressAssignCapsule(cr)
		require.ErrorContains(t, err, "lower bits not covered by prefix length are not all zero")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseAddressAssignCapsule(cr)
		require.NoError(t, err)
		for i := range data {
			_, cr, err := http3.ParseCapsule(bytes.NewReader(data[:i]))
			if err != nil {
				if i == 0 {
					require.ErrorIs(t, err, io.EOF)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				continue
			}
			_, err = parseAddressAssignCapsule(cr)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		}
	})
}

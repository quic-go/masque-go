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

func TestWriteAddressAssignCapsule(t *testing.T) {
	c := &addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	buf := &bytes.Buffer{}
	require.NoError(t, c.marshal(buf))
	typ, cr, err := http3.ParseCapsule(buf)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	parsed, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, buf.Len())
}

func TestParseAddressAssignCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressAssign, func(r io.Reader) error {
		_, err := parseAddressAssignCapsule(quicvarint.NewReader(r))
		return err
	})
}

func testParseAddressCapsuleInvalid(t *testing.T, typ http3.CapsuleType, f func(r io.Reader) error) {
	t.Run("invalid IP version", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 5)              // Invalid IP version (not 4 or 6)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "invalid IP version: 5")
	})

	t.Run("invalid prefix length", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 33) // too long IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "prefix length 33 exceeds IP address length (32)")
	})

	t.Run("lower bits not covered by prefix length are not all zero", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)                                    // Request ID
		addr1 = append(addr1, 4)                                                 // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // non-zero lower bits
		addr1 = append(addr1, 28)                                                // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1))) // Length
		data = append(data, addr1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.ErrorContains(t, f(cr), "lower bits not covered by prefix length are not all zero")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32)             // IP Prefix Length
		addr2 := quicvarint.Append(nil, 1338) // Request ID
		addr2 = append(addr2, 6)              // IPv6
		addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
		addr2 = append(addr2, 128) // IP Prefix Length
		data := quicvarint.Append(nil, uint64(typ))
		data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
		data = append(data, addr1...)
		data = append(data, addr2...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		require.NoError(t, f(cr))
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

func TestParseAddressRequestCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length
	data := quicvarint.Append(nil, uint64(capsuleTypeAddressRequest))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	capsule, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.RequestedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestWriteAddressRequestCapsule(t *testing.T) {
	c := &addressRequestCapsule{
		RequestedAddresses: []RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	buf := &bytes.Buffer{}
	require.NoError(t, c.marshal(buf))
	typ, cr, err := http3.ParseCapsule(buf)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	parsed, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, buf.Len())
}

func TestParseAddressRequestCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressRequest, func(r io.Reader) error {
		_, err := parseAddressRequestCapsule(quicvarint.NewReader(r))
		return err
	})
}

func TestParseRouteAdvertisementCapsule(t *testing.T) {
	iprange1 := []byte{4}                                                          // IPv4
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // End IP
	iprange1 = append(iprange1, 13)                                                // IP Protocol
	iprange2 := []byte{6}                                                          // IPv6
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)   // Start IP
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...) // End IP
	iprange2 = append(iprange2, 37)                                                // IP Protocol

	data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
	data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2))) // Length
	data = append(data, iprange1...)
	data = append(data, iprange2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.ParseCapsule(r)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	capsule, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]IPAddressRange{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
		capsule.IPAddressRanges,
	)
	require.Zero(t, r.Len())
}

func TestWriteRouteAdvertisementCapsule(t *testing.T) {
	c := &routeAdvertisementCapsule{
		IPAddressRanges: []IPAddressRange{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
	}
	buf := &bytes.Buffer{}
	require.NoError(t, c.marshal(buf))
	typ, cr, err := http3.ParseCapsule(buf)
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	parsed, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, buf.Len())
}

func TestParseRouteAdvertisementCapsuleInvalid(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		iprange1 := []byte{5}                                                          // IPv5
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 2}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1))) // Length
		data = append(data, iprange1...)
		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "invalid IP version: 5")
	})

	t.Run("start IP is greater than end IP", func(t *testing.T) {
		iprange1 := []byte{4}                                                          // IPv4
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1))) // Length
		data = append(data, iprange1...)

		_, cr, err := http3.ParseCapsule(bytes.NewReader(data))
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.ErrorContains(t, err, "start IP is greater than end IP")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		iprange1 := []byte{4}                                                          // IPv4
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{2, 2, 2, 2}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol

		iprange2 := []byte{6}                                                          // IPv6
		iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)   // Start IP
		iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...) // End IP
		iprange2 = append(iprange2, 37)                                                // IP Protocol

		data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
		data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2))) // Length
		data = append(data, iprange1...)
		data = append(data, iprange2...)

		r := bytes.NewReader(data)
		_, cr, err := http3.ParseCapsule(r)
		require.NoError(t, err)
		_, err = parseRouteAdvertisementCapsule(cr)
		require.NoError(t, err)
		require.Zero(t, r.Len())
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
			_, err = parseRouteAdvertisementCapsule(cr)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		}
	})
}

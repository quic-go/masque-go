package masque

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	capsuleTypeAddressAssign      http3.CapsuleType = 1
	capsuleTypeAddressRequest     http3.CapsuleType = 2
	capsuleTypeRouteAdvertisement http3.CapsuleType = 3
)

// addressAssignCapsule represents an ADDRESS_ASSIGN capsule
type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

// AssignedAddress represents an Assigned Address within an ADDRESS_ASSIGN capsule
type AssignedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(a.RequestID) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

// addressRequestCapsule represents an ADDRESS_REQUEST capsule
type addressRequestCapsule struct {
	RequestedAddresses []RequestedAddress
}

// RequestedAddress represents an Requested Address within an ADDRESS_REQUEST capsule
type RequestedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (r RequestedAddress) len() int {
	return quicvarint.Len(r.RequestID) + 1 + r.IPPrefix.Addr().BitLen()/8 + 1
}

func parseAddressAssignCapsule(r io.Reader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func (c *addressAssignCapsule) append(b []byte) []byte {
	totalLen := 0
	for _, addr := range c.AssignedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressAssign))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.AssignedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddressRequestCapsule(r io.Reader) (*addressRequestCapsule, error) {
	var requestedAddresses []RequestedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		requestedAddresses = append(requestedAddresses, RequestedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressRequestCapsule{RequestedAddresses: requestedAddresses}, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for _, addr := range c.RequestedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.RequestedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddress(r io.Reader) (requestID uint64, prefix netip.Prefix, _ error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return 0, netip.Prefix{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix = netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return 0, netip.Prefix{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return requestID, prefix, nil
}

// routeAdvertisementCapsule represents a ROUTE_ADVERTISEMENT capsule
type routeAdvertisementCapsule struct {
	IPAddressRanges []IPAddressRange
}

// IPAddressRange represents an IP Address Range within a ROUTE_ADVERTISEMENT capsule
type IPAddressRange struct {
	StartIP    netip.Addr
	EndIP      netip.Addr
	IPProtocol uint8
}

func (r IPAddressRange) len() int { return 1 + r.StartIP.BitLen()/8 + r.EndIP.BitLen()/8 + 1 }

func parseRouteAdvertisementCapsule(r io.Reader) (*routeAdvertisementCapsule, error) {
	var ranges []IPAddressRange
	for {
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ranges = append(ranges, ipRange)
	}
	return &routeAdvertisementCapsule{IPAddressRanges: ranges}, nil
}

func (c *routeAdvertisementCapsule) append(b []byte) []byte {
	var totalLen int
	for _, ipRange := range c.IPAddressRanges {
		totalLen += ipRange.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeRouteAdvertisement))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, ipRange := range c.IPAddressRanges {
		if ipRange.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, ipRange.StartIP.AsSlice()...)
		b = append(b, ipRange.EndIP.AsSlice()...)
		b = append(b, ipRange.IPProtocol)
	}
	return b
}

func parseIPAddressRange(r io.Reader) (IPAddressRange, error) {
	var ipVersion uint8
	if err := binary.Read(r, binary.LittleEndian, &ipVersion); err != nil {
		return IPAddressRange{}, err
	}

	var startIP, endIP netip.Addr
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPAddressRange{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPAddressRange{}, err
		}
		startIP = netip.AddrFrom4(start)
		endIP = netip.AddrFrom4(end)
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPAddressRange{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPAddressRange{}, err
		}
		startIP = netip.AddrFrom16(start)
		endIP = netip.AddrFrom16(end)
	default:
		return IPAddressRange{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	if startIP.Compare(endIP) > 0 {
		return IPAddressRange{}, errors.New("start IP is greater than end IP")
	}

	var ipProtocol uint8
	if err := binary.Read(r, binary.LittleEndian, &ipProtocol); err != nil {
		return IPAddressRange{}, err
	}
	return IPAddressRange{
		StartIP:    startIP,
		EndIP:      endIP,
		IPProtocol: ipProtocol,
	}, nil
}

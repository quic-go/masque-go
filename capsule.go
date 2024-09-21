package masque

import (
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const capsuleTypeAddressAssign http3.CapsuleType = 1

// addressAssignCapsule represents an ADDRESS_ASSIGN capsule
type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

// AssignedAddress represents an Assigned Address within an ADDRESS_ASSIGN capsule
type AssignedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func parseAddressAssignCapsule(r io.Reader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for {
		addr, err := parseAssignedAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, addr)
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func parseAssignedAddress(r io.Reader) (AssignedAddress, error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return AssignedAddress{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return AssignedAddress{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return AssignedAddress{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return AssignedAddress{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return AssignedAddress{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return AssignedAddress{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return AssignedAddress{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix := netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return AssignedAddress{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return AssignedAddress{RequestID: requestID, IPPrefix: prefix}, nil
}

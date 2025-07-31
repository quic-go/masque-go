package masque

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	compressionAsignCapsuleType = 0x1C0FE323
	compressionCloseCapsuleType = 0x1C0FE324
)

type uncompressedDatagram struct {
	Addr *net.UDPAddr
	Data []byte
}

func (u uncompressedDatagram) Marshal() ([]byte, error) {
	if len(u.Addr.IP) != 4 && len(u.Addr.IP) != 16 {
		return nil, fmt.Errorf("expected IPv4 or IPv6 address, got %s", u.Addr.IP)
	}

	p2 := make([]byte, 0, 1+len(u.Addr.IP)+2+len(u.Data))
	p2 = append(p2, ipVersion(u.Addr.IP))
	p2 = append(p2, u.Addr.IP...)
	p2 = binary.BigEndian.AppendUint16(p2, uint16(u.Addr.Port))
	p2 = append(p2, u.Data...)

	return p2, nil
}

func (u *uncompressedDatagram) Unmarshal(p []byte) error {
	if len(p) < 1 {
		return fmt.Errorf("masque: datagram too small (%d bytes)", len(p))
	}

	version := p[0]
	if version == 4 {
		if len(p) < 1+4+2 {
			return fmt.Errorf("masque: datagram too small (%d bytes)", len(p))
		}

		addr := &net.UDPAddr{
			IP:   p[1 : 1+4],
			Port: int(binary.BigEndian.Uint16(p[1+4:])),
		}
		u.Addr = addr
		u.Data = p[1+4+2:]
		return nil
	} else if version == 6 {
		if len(p) < 1+16+2 {
			return fmt.Errorf("masque: datagram too small (%d bytes)", len(p))
		}

		addr := &net.UDPAddr{
			IP:   p[1 : 1+16],
			Port: int(binary.BigEndian.Uint16(p[1+16:])),
		}
		u.Addr = addr
		u.Data = p[1+16+2:]
		return nil
	} else {
		return fmt.Errorf("masque: invalid IP version: %d", version)
	}
}

func prependContextID(p []byte, contextID uint64) []byte {
	p2 := make([]byte, 0, quicvarint.Len(contextID)+len(p))
	p2 = quicvarint.Append(p2, contextID)
	p2 = append(p2, p...)
	return p2
}

type compressionAssignCapsule struct {
	ContextID uint64
	Addr      *net.UDPAddr
}

func (c compressionAssignCapsule) Marshal() ([]byte, error) {
	if c.Addr == nil {
		// For uncompressed datagrams.
		p2 := make([]byte, 0, quicvarint.Len(c.ContextID))
		p2 = quicvarint.Append(p2, c.ContextID)
		p2 = append(p2, 0)
		return p2, nil
	}

	if len(c.Addr.IP) != 4 && len(c.Addr.IP) != 16 {
		return nil, fmt.Errorf("expected IPv4 or IPv6 address, got %s", c.Addr.IP)
	}

	p2 := make([]byte, 0, quicvarint.Len(c.ContextID)+1+len(c.Addr.IP)+2)
	p2 = quicvarint.Append(p2, c.ContextID)
	p2 = append(p2, ipVersion(c.Addr.IP))
	p2 = append(p2, c.Addr.IP...)
	p2 = binary.BigEndian.AppendUint16(p2, uint16(c.Addr.Port))
	return p2, nil
}

func (c *compressionAssignCapsule) Unmarshal(p []byte) error {
	contextID, n, err := quicvarint.Parse(p)
	if err != nil {
		return fmt.Errorf("masque: failed to read varint: %w", err)
	}

	if len(p) < n+1 {
		return fmt.Errorf("masque: capsule too small (%d bytes)", len(p))
	}

	version := p[n]
	if version == 0 {
		c.ContextID = contextID
		return nil
	} else if version == 4 {
		if len(p) < n+1+4+2 {
			return fmt.Errorf("masque: capsule too small (%d bytes)", len(p))
		}

		c.ContextID = contextID
		c.Addr = &net.UDPAddr{
			IP:   p[n+1 : n+1+4],
			Port: int(binary.BigEndian.Uint16(p[n+1+4:])),
		}
		return nil
	} else if version == 6 {
		if len(p) < n+1+16+2 {
			return fmt.Errorf("masque: capsule too small (%d bytes)", len(p))
		}

		c.ContextID = contextID
		c.Addr = &net.UDPAddr{
			IP:   p[n+1 : n+1+16],
			Port: int(binary.BigEndian.Uint16(p[n+1+16:])),
		}
		return nil
	} else {
		return fmt.Errorf("masque: invalid IP version: %d", version)
	}
}

type compressionCloseCapsule struct {
	ContextID uint64
}

func (c compressionCloseCapsule) Marshal() ([]byte, error) {
	p2 := make([]byte, 0, quicvarint.Len(c.ContextID))
	p2 = quicvarint.Append(p2, c.ContextID)
	return p2, nil
}

func (c *compressionCloseCapsule) Unmarshal(p []byte) error {
	contextID, _, err := quicvarint.Parse(p)
	if err != nil {
		return fmt.Errorf("masque: failed to read varint: %w", err)
	}

	c.ContextID = contextID

	return nil
}

func ipVersion(ip net.IP) byte {
	if len(ip) == 4 {
		return 4
	} else if len(ip) == 16 {
		return 6
	} else {
		panic("invalid IP address")
	}
}

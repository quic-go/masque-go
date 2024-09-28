package masque

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type appendable interface{ append([]byte) []byte }

type writeCapsule struct {
	capsule appendable
	result  chan error
}

// ProxiedIPConn is a connection that proxies IP packets over HTTP/3.
type ProxiedIPConn struct {
	str    http3.Stream
	writes chan writeCapsule

	peerAddresses []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes   []IPRoute      // IP routes that we advertised to the peer

	assignedAddressNotify chan struct{}
	assignedAddresses     atomic.Pointer[[]netip.Prefix]
	availableRoutesNotify chan struct{}
	availableRoutes       atomic.Pointer[[]IPRoute]
}

func newProxiedIPConn(str http3.Stream) *ProxiedIPConn {
	c := &ProxiedIPConn{
		str:                   str,
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("handling stream failed: %v", err)
		}
	}()
	go func() {
		if err := c.writeToStream(); err != nil {
			log.Printf("writing to stream failed: %v", err)
		}
	}()
	return c
}

// AdvertiseRoute informs the peer about available routes.
// This function can be called multiple times, but only the routes from the most recent call will be active.
// Previous route advertisements are overwritten by each new call to this function.
func (c *ProxiedIPConn) AdvertiseRoute(ctx context.Context, routes []IPRoute) error {
	c.localRoutes = slices.Clone(routes)
	for _, route := range routes {
		if route.StartIP.Compare(route.EndIP) == 1 {
			return fmt.Errorf("invalid route advertising start_ip: %s larger than %s", route.StartIP, route.EndIP)
		}
	}
	return c.sendCapsule(ctx, &routeAdvertisementCapsule{IPAddressRanges: routes})
}

// AssignAddresses assigned address prefixes to the peer.
// This function can be called multiple times, but only the addresses from the most recent call will be active.
// Previous address assignments are overwritten by each new call to this function.
func (c *ProxiedIPConn) AssignAddresses(ctx context.Context, prefixes []netip.Prefix) error {
	c.peerAddresses = slices.Clone(prefixes)
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	return c.sendCapsule(ctx, capsule)
}

func (c *ProxiedIPConn) sendCapsule(ctx context.Context, capsule appendable) error {
	res := make(chan error, 1)
	select {
	case c.writes <- writeCapsule{
		capsule: capsule,
		result:  res,
	}:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-res:
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *ProxiedIPConn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.assignedAddressNotify:
		return *c.assignedAddresses.Load(), nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *ProxiedIPConn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.assignedAddressNotify:
		return *c.availableRoutes.Load(), nil
	}
}

func (c *ProxiedIPConn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.assignedAddresses.Store(&prefixes)
			select {
			case c.assignedAddressNotify <- struct{}{}:
			default:
			}
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(r); err != nil {
				return err
			}
			return errors.New("masque: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(r)
			if err != nil {
				return err
			}
			c.availableRoutes.Store(&capsule.IPAddressRanges)
			select {
			case c.availableRoutesNotify <- struct{}{}:
			default:
			}
		default:
			return fmt.Errorf("unknown capsule type: %d", t)
		}
	}
}

func (c *ProxiedIPConn) writeToStream() error {
	buf := make([]byte, 0, 1024)
	for {
		req, ok := <-c.writes
		if !ok {
			return nil
		}
		buf = req.capsule.append(buf)
		_, err := c.str.Write(buf)
		req.result <- err
		if err != nil {
			return err
		}
		buf = buf[:0]
	}
}

func (c *ProxiedIPConn) Read(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, err
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		return 0, fmt.Errorf("masque: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of IP payloads.
		goto start
	}
	if err := c.handleIncomingPacket(data[n:]); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	return copy(b, data[n:]), nil
}

func (c *ProxiedIPConn) handleIncomingPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch ipVersion(data) {
	default:
		return fmt.Errorf("masque: unknown IP versions: %d", data[0])
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("masque: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("masque: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	if !slices.ContainsFunc(c.peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
		// TODO: send ICMP
		return fmt.Errorf("masque: datagram source address not allowed: %s", src)
	}
	isAllowedDest := slices.ContainsFunc(c.localRoutes, func(r IPRoute) bool {
		if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
			return false
		}
		if r.IPProtocol != 0 && r.IPProtocol != ipProto {
			return false
		}
		return true
	})
	if !isAllowedDest {
		// TODO: send ICMP
		return fmt.Errorf("masque: datagram destination address / IP protocol not allowed: %s (protocol %d)", dst, ipProto)
	}
	return nil
}

func (c *ProxiedIPConn) Write(b []byte) (n int, err error) {
	// TODO: implement src, dst and ipproto checks
	if len(b) == 0 {
		return 0, nil
	}
	switch ipVersion(b) {
	default:
		return 0, fmt.Errorf("masque: unknown IP versions: %d", b[0])
	case 4:
		if len(b) < 20 {
			return 0, fmt.Errorf("masque: IPv4 packet too short")
		}
		ttl := b[8]
		if ttl <= 1 {
			return 0, fmt.Errorf("masque: datagram TTL too small: %d", ttl)
		}
		b[8]-- // Decrement TTL
		// TODO: maybe recalculate the checksum?
	case 6:
		// TODO: IPv6 support
		return 0, errors.New("IPv6 currently not supported")
	}
	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return len(b), c.str.SendDatagram(data)
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }

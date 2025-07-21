package masque

import (
	"fmt"
	"net"
	"sync"
)

type compression struct {
	addr        *net.UDPAddr
	acknoledged chan struct{}
}

type compressionTable struct {
	mu          sync.RWMutex
	isForClient bool

	uncompressedContextID *uint64

	compressions map[uint64]compression
}

func newCompressionTable(isForClient bool) *compressionTable {
	return &compressionTable{
		isForClient:  isForClient,
		compressions: make(map[uint64]compression),
	}
}

// lookupAddr looks up the address in the compression table to find the context ID
// to use when sending datagrams with the given address.
// If no context ID can be found, `found` is false and the datagram has to be dropped.
// If `found` is true, `isCompressed` is true if the datagram is compressed, false if it is uncompressed.
func (t *compressionTable) lookupAddr(addr *net.UDPAddr) (contextID uint64, isCompressed bool, found bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Find context ID for compression.
	for contextID, compression := range t.compressions {
		if compression.addr.IP.Equal(addr.IP) && compression.addr.Port == addr.Port {
			return contextID, true, true
		}
	}

	// Find context ID for uncompressed datagrams.
	if t.uncompressedContextID != nil {
		return *t.uncompressedContextID, false, true
	}

	return 0, false, false
}

// lookupContextID looks up the context ID in the compression table.
// If the context ID has been assigned, `found` is true.
// `addr` is `nil` if the context ID used for uncompressed datagrams.
func (t *compressionTable) lookupContextID(contextID uint64) (addr *net.UDPAddr, found bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	compression, found := t.compressions[contextID]
	if found {
		return compression.addr, true
	}

	if t.uncompressedContextID != nil && *t.uncompressedContextID == contextID {
		return nil, true
	}

	return nil, false
}

// findUnusedContextID finds the next unused context ID to be used in conmpresion assignment.
func (t *compressionTable) findUnusedContextID() (contextID uint64) {
	// TODO: When is locking necessary?
	// t.mu.RLock()
	// defer t.mu.RUnlock()

	highest := uint64(0)

	if t.uncompressedContextID != nil {
		return *t.uncompressedContextID
	}

	for contextID := range t.compressions {
		if contextID > highest {
			highest = contextID
		}
	}

	nextContextID := highest + 1

	if t.isForClient {
		// Clients use even context IDs.
		if nextContextID%2 != 0 {
			nextContextID++
		}
	} else {
		// Proxies use odd context IDs.
		if highest%2 == 0 {
			highest++
		}
	}

	return nextContextID
}

func (t *compressionTable) newUncompressedAssignment() (contextID uint64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.uncompressedContextID != nil {
		return 0, fmt.Errorf("uncompressed context ID already assigned")
	}

	contextID = t.findUnusedContextID()
	t.uncompressedContextID = &contextID

	return contextID, nil
}

func (t *compressionTable) newCompressedAssignment(addr *net.UDPAddr) (newContextID uint64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if addr == nil {
		return 0, fmt.Errorf("address is nil")
	}

	// Lookup is the address is already registered for compression.
	_, isCompressed, found := t.lookupAddr(addr)
	if found && isCompressed {
		return 0, fmt.Errorf("address is already registered for compression")
	}

	newContextID = t.findUnusedContextID()
	t.compressions[newContextID] = compression{addr: addr, acknoledged: make(chan struct{})}

	return newContextID, nil
}

func (t *compressionTable) handleAssignmentCapsule(capsule compressionAssignCapsule) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isForClient {
		// We are a client. Check if the assignment was initiated by us.
		if capsule.ContextID%2 == 0 {
			// Even context ID has to be us.
			// TODO: Ignore this for now. In the future, we should validate and acknowledge the assignment.
			return nil
		} else {
			// Odd context ID has to be the proxy.
			if capsule.Addr == nil {
				if t.uncompressedContextID != nil {
					return fmt.Errorf("uncompressed context ID already assigned")
				}

				t.uncompressedContextID = &capsule.ContextID
				return nil
			}

			_, found := t.compressions[capsule.ContextID]
			if found {
				return fmt.Errorf("proxy already assigned context ID %d", capsule.ContextID)
			}

			ack := make(chan struct{})
			close(ack)
			t.compressions[capsule.ContextID] = compression{addr: capsule.Addr, acknoledged: ack}

			return nil
		}
	} else {
		// We are a proxy. Check if the assignment was initiated by us.
		if capsule.ContextID%2 != 0 {
			// Odd context ID has to be us.
			// TODO: Ignore this for now. In the future, we should validate and acknowledge the assignment.
			return nil
		} else {
			// Even context ID has to be the client.
			if capsule.Addr == nil {
				if t.uncompressedContextID != nil {
					return fmt.Errorf("uncompressed context ID already assigned")
				}

				t.uncompressedContextID = &capsule.ContextID
				return nil
			}

			_, found := t.compressions[capsule.ContextID]
			if found {
				return fmt.Errorf("client already assigned context ID %d", capsule.ContextID)
			}

			ack := make(chan struct{})
			close(ack)
			t.compressions[capsule.ContextID] = compression{addr: capsule.Addr, acknoledged: ack}

			return nil
		}
	}
}

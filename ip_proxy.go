package masque

import (
	"net"
	"net/http"
	"sync/atomic"

	"github.com/quic-go/quic-go/http3"
)

type IPProxy struct {
	closed atomic.Bool
}

func (s *IPProxy) Proxy(w http.ResponseWriter, _ *ConnectIPRequest) (*ProxiedIPConn, error) {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil, net.ErrClosed
	}
	w.Header().Set(capsuleHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()
	return newProxiedIPConn(str), nil
}

package masque

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// ProxyRequest is the parsed CONNECT-UDP request returned from ParseProxyRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type ProxyRequest struct {
	Target string
	Host   string
}

// ProxyRequestParseError is returned from ParseProxyRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type ProxyRequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *ProxyRequestParseError) Error() string { return e.Err.Error() }
func (e *ProxyRequestParseError) Unwrap() error { return e.Err }

// ParseProxyRequest parses a CONNECT-UDP request.
// The template is the URI template that clients will use to configure this UDP proxy.
func ParseProxyRequest(r *http.Request, template *uritemplate.Template) (*ProxyRequest, error) {
	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}

	if r.Method != http.MethodConnect {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Proto != requestProtocol {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if r.Host != u.Host {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}
	// The capsule protocol header is optional, but if it's present,
	// we need to validate its value.
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if ok {
		item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
		if err != nil {
			return nil, &ProxyRequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
			}
		}
		if v, ok := item.Value.(bool); !ok {
			return nil, &ProxyRequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
			}
		} else if !v {
			return nil, &ProxyRequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
			}
		}
	}

	match := template.Match(r.URL.String())
	targetHost := match.Get(uriTemplateTargetHost).String()
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHost == "" || targetPortStr == "" {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port"),
		}
	}
	// IPv6 addresses need to be enclosed in [], otherwise resolving the address will fail.
	if strings.Contains(targetHost, ":") {
		targetHost = "[" + targetHost + "]"
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_port: %w", err),
		}
	}
	return &ProxyRequest{
		Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
		Host:   r.Host,
	}, nil
}

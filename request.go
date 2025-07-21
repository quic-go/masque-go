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

const requestProtocol = "connect-udp"

var sfTrueValue string

const ConnectUDPBindHeader = "Connect-Udp-Bind" // Udp not UDP due to Go's header canonicalization
const ProxyPublicAddressHeader = "Proxy-Public-Address"

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal structured fields header value: %v", err))
	}
	sfTrueValue = v
}

// Request is the parsed CONNECT-UDP request returned from ParseRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type Request struct {
	Target string
	Bind   bool
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

// ParseRequest parses a CONNECT-UDP request.
// The template is the URI template that clients will use to configure this UDP proxy.
func ParseRequest(r *http.Request, template *uritemplate.Template) (*Request, error) {
	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}

	if r.Method != http.MethodConnect {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Proto != requestProtocol {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if r.Host != u.Host {
		return nil, &RequestParseError{
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
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
			}
		}
		if v, ok := item.Value.(bool); !ok {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
			}
		} else if !v {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
			}
		}
	}

	// Validate Conect-UDP-Bind header if present
	bind := false
	bindHeaderValues, ok := r.Header[ConnectUDPBindHeader]
	if ok {
		item, err := httpsfv.UnmarshalItem(bindHeaderValues)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("invalid bind header value: %s", bindHeaderValues),
			}
		}
		if v, ok := item.Value.(bool); !ok {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("incorrect bind header value type: %s", reflect.TypeOf(item.Value)),
			}
		} else if v {
			bind = true
		}
	}

	match := template.Match(r.URL.String())
	targetHost := unescape(match.Get(uriTemplateTargetHost).String())
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHost == "" || targetPortStr == "" {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port"),
		}
	}

	var target string
	if !bind {
		// IPv6 addresses need to be enclosed in [], otherwise resolving the address will fail.
		if strings.Contains(targetHost, ":") {
			targetHost = "[" + targetHost + "]"
		}
		targetPort, err := strconv.Atoi(targetPortStr)
		if err != nil {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("failed to decode target_port: %w", err),
			}
		}

		target = fmt.Sprintf("%s:%d", targetHost, targetPort)
	} else {
		if targetHost != "*" || targetPortStr != "*" {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusBadRequest,
				Err:        fmt.Errorf("target_host and target_port must be * when binding is requested"),
			}
		}

		target = fmt.Sprintf("%s:%s", targetHost, targetPortStr)
	}

	return &Request{Target: target, Bind: bind}, nil
}

func escape(s string) string   { return strings.ReplaceAll(s, ":", "%3A") }
func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }

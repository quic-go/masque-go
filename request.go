package masque

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"

	"github.com/dunglas/httpsfv"
	"github.com/yosida95/uritemplate/v3"
)

const (
	requestProtocol = "connect-udp"
	capsuleHeader   = "Capsule-Protocol"
)

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// Request is the parsed CONNECT-UDP request returned from ParseRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type Request struct {
	Target string
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
	// TODO: check :authority
	capsuleHeaderValues, ok := r.Header[capsuleHeader]
	if !ok {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing Capsule-Protocol header"),
		}
	}
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

	match := template.Match(r.URL.String())
	targetHostEncoded := match.Get(uriTemplateTargetHost).String()
	targetPortStr := match.Get(uriTemplateTargetPort).String()
	if targetHostEncoded == "" || targetPortStr == "" {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("expected target_host and target_port"),
		}
	}
	targetHost, err := url.QueryUnescape(targetHostEncoded)
	if err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_host: %w", err),
		}
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_port: %w", err),
		}
	}
	return &Request{Target: fmt.Sprintf("%s:%d", targetHost, targetPort)}, nil
}

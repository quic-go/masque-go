package masque

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/yosida95/uritemplate/v3"
)

const capsuleHeader = "Capsule-Protocol"

const (
	connectUDPRequestProtocol    = "connect-udp"
	connectUDPTemplateTargetHost = "target_host"
	connectUDPTemplateTargetPort = "target_port"
)

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// ConnectUDPRequest is the parsed CONNECT-UDP request returned from ParseConnectUDPRequest.
// Target is the target server that the client requests to connect to.
// It can either be DNS name:port or an IP:port.
type ConnectUDPRequest struct {
	Target string
}

// RequestParseError is returned from ParseConnectUDPRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

func verifyConnectUDPAndIPRequest(r *http.Request, template *uritemplate.Template) *RequestParseError {
	u, err := url.Parse(template.Raw())
	if err != nil {
		return &RequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}
	if r.Method != http.MethodConnect {
		return &RequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Host != u.Host {
		return &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}
	capsuleHeaderValues, ok := r.Header[capsuleHeader]
	if !ok {
		return &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing Capsule-Protocol header"),
		}
	}
	item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
	if err != nil {
		return &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
		}
	}
	if v, ok := item.Value.(bool); !ok {
		return &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
		}
	} else if !v {
		return &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
		}
	}
	return nil
}

// ParseConnectUDPRequest parses a CONNECT-UDP request.
// The template is the URI template that clients will use to configure this UDP proxy.
func ParseConnectUDPRequest(r *http.Request, template *uritemplate.Template) (*ConnectUDPRequest, error) {
	if r.Proto != connectUDPRequestProtocol {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if err := verifyConnectUDPAndIPRequest(r, template); err != nil {
		return nil, err
	}

	match := template.Match(r.URL.String())
	targetHost := unescape(match.Get(connectUDPTemplateTargetHost).String())
	targetPortStr := match.Get(connectUDPTemplateTargetPort).String()
	if targetHost == "" || targetPortStr == "" {
		return nil, &RequestParseError{
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
		return nil, &RequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("failed to decode target_port: %w", err),
		}
	}
	return &ConnectUDPRequest{Target: fmt.Sprintf("%s:%d", targetHost, targetPort)}, nil
}

func escape(s string) string   { return strings.ReplaceAll(s, ":", "%3A") }
func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }

const connectIPRequestProtocol = "connect-ip"

// ConnectIPRequest is the parsed CONNECT-IP request returned from ParseConnectIPRequest.
// It currently doesn't have any fields, since masque-go doesn't support IP flow forwarding.
type ConnectIPRequest struct{}

func ParseConnectIPRequest(r *http.Request, template *uritemplate.Template) (*ConnectIPRequest, error) {
	if len(template.Varnames()) > 0 {
		return nil, errors.New("masque-go currently does not support IP flow forwarding")
	}
	if r.Proto != connectIPRequestProtocol {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if err := verifyConnectUDPAndIPRequest(r, template); err != nil {
		return nil, err
	}
	return &ConnectIPRequest{}, nil
}

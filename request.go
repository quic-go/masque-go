package masque

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const ConnectUDP = "connect-udp"
const ConnectTCP = "connect-tcp-08"

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
	Protocol string // "connect-udp" or "connect-tcp"
	Host   string
	Target string
	Body   io.ReadCloser
}

// RequestParseError is returned from ParseRequest if parsing the CONNECT-UDP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type RequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *RequestParseError) Error() string { return e.Err.Error() }
func (e *RequestParseError) Unwrap() error { return e.Err }

func getURL(r *http.Request) url.URL {
	u := *r.URL
	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		u.Scheme = "https"
		if r.TLS == nil {
			u.Scheme = "http"
		}
	}
	return u
}

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

	var protocol string
	if r.ProtoMajor == 2 {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("HTTP/2 is not supported"),
		}
	} else if r.ProtoMajor == 1 {
		if r.Method != http.MethodGet {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusMethodNotAllowed,
				Err:        fmt.Errorf("expected GET request in HTTP/1.1, got %s", r.Method),
			}
		}

		protocol = r.Header.Get("upgrade")
	} else if r.ProtoMajor == 3 {
		if r.Method != http.MethodConnect {
			return nil, &RequestParseError{
				HTTPStatus: http.StatusMethodNotAllowed,
				Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
			}
		}

		protocol = r.Proto
	} else {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected HTTP version: %d", r.ProtoMajor),
		}
	}
	if protocol != ConnectUDP && protocol != ConnectTCP {
		return nil, &RequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", protocol),
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

	requestURL := getURL(r)
	match := template.Match(requestURL.String())
	targetHost := unescape(match.Get(uriTemplateTargetHost).String())
	targetPortStr := match.Get(uriTemplateTargetPort).String()
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
	return &Request{
		Protocol: protocol,
		Host:   r.Host,
		Target: fmt.Sprintf("%s:%d", targetHost, targetPort),
		Body: r.Body,
	}, nil
}

func escape(s string) string   { return strings.ReplaceAll(s, ":", "%3A") }
func unescape(s string) string { return strings.ReplaceAll(s, "%3A", ":") }

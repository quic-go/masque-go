# masque-go

[![Documentation](https://img.shields.io/badge/docs-quic--go.net-red?style=flat)](https://quic-go.net/docs/connect-udp)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/masque-go)](https://pkg.go.dev/github.com/quic-go/masque-go)
[![Code Coverage](https://img.shields.io/codecov/c/github/quic-go/masque-go/master.svg?style=flat-square)](https://codecov.io/gh/quic-go/masque-go/)

masque-go is an implementation of the CONNECT-UDP protocol [RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298), based on [quic-go](https://github.com/quic-go/quic-go). It provides both a client and a proxy implementation.

Detailed documentation can be found on [quic-go.net](https://quic-go.net/docs/connect-udp/).

## Demo Usage

These are some examples of how to use the included demo utilities.

### Using unencrypted HTTP/1.1 (http://)

Terminal 1: Proxy setup
```sh
go run ./cmd/proxy -b 127.0.0.1:8088 -t "http://127.0.0.1:8088/masque?target_host={target_host}&target_port={target_port}"
```
Terminal 2
```sh
# Fetch over UDP
go run ./cmd/client -t "http://127.0.0.1:8088/masque?target_host={target_host}&target_port={target_port}" -quic=false https://http3.is
```

### Using HTTP with TLS and QUIC (https://)

> [!WARNING] These examples use the `-insecure-tls` flag to disable TLS certificate verification.

Terminal 1: Proxy setup
```sh
openssl req -x509 -newkey rsa:4096 -days 3650 -noenc -keyout masque-test.key -out masque-test.crt -subj "/CN=masque.test"

go run ./cmd/proxy -b 127.0.0.1:8443 -k masque-test.key -c masque-test.crt -t "https://127.0.0.1:8443/masque?target_host={target_host}&target_port={target_port}"
```
Terminal 2
```sh
# Fetch over UDP using HTTP/3 Datagrams
go run ./cmd/client -t "https://127.0.0.1:8443/masque?target_host={target_host}&target_port={target_port}" -insecure-tls https://http3.is

# Fetch over UDP using HTTP/1.1
go run ./cmd/client -t "https://127.0.0.1:8443/masque?target_host={target_host}&target_port={target_port}" -insecure-tls -quic=false https://http3.is
```

## Release Policy

masque-go always aims to support the latest two Go releases.

## Contributing

We are always happy to welcome new contributors! If you have any questions, please feel free to reach out by opening an issue or leaving a comment.

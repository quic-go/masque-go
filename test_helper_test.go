package masque_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

var (
	tlsConf  *tls.Config
	certPool *x509.CertPool
)

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, caPrivateKey, nil
}

func generateLeafCert(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	certTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost", "127.0.0.1"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTempl, ca, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey, nil
}

func newUDPConnLocalhost(t testing.TB) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func newConnPair(t *testing.T) (client, server quic.EarlyConnection) {
	t.Helper()

	ln, err := quic.ListenEarly(
		newUDPConnLocalhost(t),
		tlsConf,
		&quic.Config{
			InitialStreamReceiveWindow:     1 << 60,
			InitialConnectionReceiveWindow: 1 << 60,
			EnableDatagrams:                true,
		},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cl, err := quic.DialEarly(
		ctx,
		newUDPConnLocalhost(t),
		ln.Addr(),
		&tls.Config{
			ServerName: "localhost",
			NextProtos: []string{http3.NextProtoH3},
			RootCAs:    certPool,
		},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	require.True(t, cl.ConnectionState().SupportsDatagrams)
	t.Cleanup(func() { cl.CloseWithError(0, "") })

	conn, err := ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	select {
	case <-conn.HandshakeComplete():
		require.True(t, conn.ConnectionState().SupportsDatagrams)
	case <-ctx.Done():
		t.Fatal("timeout")
	}
	return cl, conn
}

func init() {
	ca, caPrivateKey, err := generateCA()
	if err != nil {
		log.Fatal("failed to generate CA certificate:", err)
	}
	leafCert, leafPrivateKey, err := generateLeafCert(ca, caPrivateKey)
	if err != nil {
		log.Fatal("failed to generate leaf certificate:", err)
	}
	certPool = x509.NewCertPool()
	certPool.AddCert(ca)
	tlsConf = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafPrivateKey,
		}},
		NextProtos: []string{http3.NextProtoH3},
	}
}

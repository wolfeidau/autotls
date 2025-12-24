package autotls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

const (
	DefaultCommonName = "localhost"
)

var DefaultIPs = []string{
	"127.0.0.1",
	"::1",
}

func GenerateSelfSignedCert(commonName string, ips []string) (tls.Certificate, error) {
	if len(ips) == 0 {
		ips = DefaultIPs
	}

	if commonName == "" {
		commonName = DefaultCommonName
	}

	ipsStr := make([]net.IP, len(ips))
	for i, ip := range ips {
		ipsStr[i] = net.ParseIP(ip)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // Valid for 24 hours
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: ipsStr,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}, nil
}

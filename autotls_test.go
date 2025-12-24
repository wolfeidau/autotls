package autotls

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestGenerateSelfSignedCert_DefaultValues(t *testing.T) {
	cert, err := GenerateSelfSignedCert("", []string{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatal("Certificate slice is empty")
	}

	if cert.PrivateKey == nil {
		t.Fatal("PrivateKey is nil")
	}

	// Parse the certificate to verify its contents
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if parsedCert.Subject.CommonName != DefaultCommonName {
		t.Errorf("Expected CommonName %q, got %q", DefaultCommonName, parsedCert.Subject.CommonName)
	}

	if len(parsedCert.IPAddresses) != len(DefaultIPs) {
		t.Errorf("Expected %d IP addresses, got %d", len(DefaultIPs), len(parsedCert.IPAddresses))
	}
}

func TestGenerateSelfSignedCert_CustomValues(t *testing.T) {
	commonName := "example.com"
	ips := []string{"192.168.1.1", "10.0.0.1"}

	cert, err := GenerateSelfSignedCert(commonName, ips)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if parsedCert.Subject.CommonName != commonName {
		t.Errorf("Expected CommonName %q, got %q", commonName, parsedCert.Subject.CommonName)
	}

	if len(parsedCert.IPAddresses) != len(ips) {
		t.Errorf("Expected %d IP addresses, got %d", len(ips), len(parsedCert.IPAddresses))
	}

	for i, ip := range ips {
		expected := net.ParseIP(ip)
		if !parsedCert.IPAddresses[i].Equal(expected) {
			t.Errorf("IP address mismatch at index %d: expected %s, got %s", i, ip, parsedCert.IPAddresses[i])
		}
	}
}

func TestGenerateSelfSignedCert_ValidityPeriod(t *testing.T) {
	cert, err := GenerateSelfSignedCert("", []string{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	now := time.Now()

	if parsedCert.NotBefore.After(now) {
		t.Error("NotBefore is in the future")
	}

	if parsedCert.NotAfter.Before(now) {
		t.Error("NotAfter is in the past")
	}

	// Check that validity period is approximately 24 hours
	expectedExpiry := parsedCert.NotBefore.Add(24 * time.Hour)
	duration := parsedCert.NotAfter.Sub(expectedExpiry)
	if duration < 0 {
		duration = -duration
	}
	if duration > time.Minute {
		t.Errorf("Validity period differs from 24 hours by more than a minute")
	}
}

func TestGenerateSelfSignedCert_PrivateKeyType(t *testing.T) {
	cert, err := GenerateSelfSignedCert("", []string{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Verify that the private key is an RSA key
	_, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("PrivateKey is not an RSA private key")
	}
}

func TestGenerateSelfSignedCert_KeyUsage(t *testing.T) {
	cert, err := GenerateSelfSignedCert("", []string{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Check KeyUsage flags
	expectedKeyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if parsedCert.KeyUsage != expectedKeyUsage {
		t.Errorf("Expected KeyUsage %v, got %v", expectedKeyUsage, parsedCert.KeyUsage)
	}

	// Check ExtKeyUsage
	if len(parsedCert.ExtKeyUsage) != 1 || parsedCert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("Expected ExtKeyUsage [ServerAuth], got %v", parsedCert.ExtKeyUsage)
	}
}

func TestGenerateSelfSignedCert_TLSUsable(t *testing.T) {
	cert, err := GenerateSelfSignedCert("localhost", []string{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Verify it can be used as a tls.Certificate
	if len(cert.Certificate) == 0 {
		t.Fatal("Certificate is not properly formatted for TLS")
	}

	if cert.PrivateKey == nil {
		t.Fatal("PrivateKey is required for TLS")
	}
}

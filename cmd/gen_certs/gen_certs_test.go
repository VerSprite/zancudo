package main

import (
	"crypto/rsa"
	"crypto/x509"
	"slices"
	"testing"
)

func TestParseHostArg(t *testing.T) {
	tests := []struct {
		arg  string
		want string
	}{
		{"broker.local", "broker.local"},
		{"broker.local:8883", "broker.local"},
		{"10.0.0.5", "10.0.0.5"},
		{"10.0.0.5:8883", "10.0.0.5"},
		{"::1", "::1"},
		{"[::1]:8883", "::1"},
		{"[::1]", "::1"},
		{"localhost:8888", "localhost"},
	}
	for _, tt := range tests {
		got, err := parseHostArg(tt.arg)
		if err != nil {
			t.Errorf("parseHostArg(%q) returned error: %v", tt.arg, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseHostArg(%q) = %q, want %q", tt.arg, got, tt.want)
		}
	}
}

func TestParseHostArgRejectsEmptyHost(t *testing.T) {
	for _, arg := range []string{"", ":8883", "[]"} {
		if got, err := parseHostArg(arg); err == nil {
			t.Errorf("parseHostArg(%q) = %q, want error", arg, got)
		}
	}
}

// newLeaf builds a certificate the same way the "new" subcommand does.
func newLeaf(t *testing.T, host string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	cert, _, err := generateSignedCertificate(newLeafTemplate(host), "", caCert, caKey)
	if err != nil {
		t.Fatalf("generateSignedCertificate(%q): %v", host, err)
	}
	return cert
}

func TestNewLeafCoversRequestedHost(t *testing.T) {
	tests := []struct {
		host       string
		valid      []string
		notCovered []string
	}{
		{"broker.local", []string{"broker.local"}, []string{"127.0.0.1", "other.local"}},
		{"10.0.0.5", []string{"10.0.0.5"}, []string{"127.0.0.1", "10.0.0.6"}},
		{"fd00::5", []string{"fd00::5"}, []string{"::1"}},
		{"127.0.0.1", []string{"127.0.0.1"}, []string{"localhost"}},
	}
	for _, tt := range tests {
		cert := newLeaf(t, tt.host, nil, nil)
		if cert.Subject.CommonName != tt.host {
			t.Errorf("%s: CommonName = %q, want %q", tt.host, cert.Subject.CommonName, tt.host)
		}
		for _, name := range tt.valid {
			if err := cert.VerifyHostname(name); err != nil {
				t.Errorf("%s: cert should be valid for %q: %v", tt.host, name, err)
			}
		}
		for _, name := range tt.notCovered {
			if err := cert.VerifyHostname(name); err == nil {
				t.Errorf("%s: cert should NOT be valid for %q", tt.host, name)
			}
		}
	}
}

func TestNewLeafLocalhostAddsLoopbackIPs(t *testing.T) {
	for _, host := range []string{"localhost", "LocalHost"} {
		cert := newLeaf(t, host, nil, nil)
		for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
			if err := cert.VerifyHostname(name); err != nil {
				t.Errorf("%s: cert should be valid for %q: %v", host, name, err)
			}
		}
	}
}

func TestNewLeafUsages(t *testing.T) {
	cert := newLeaf(t, "broker.local", nil, nil)
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if !slices.Contains(cert.ExtKeyUsage, eku) {
			t.Errorf("ExtKeyUsage %v missing %v", cert.ExtKeyUsage, eku)
		}
	}
	wantKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if cert.KeyUsage&wantKU != wantKU {
		t.Errorf("KeyUsage = %v, want at least %v", cert.KeyUsage, wantKU)
	}
	if cert.IsCA {
		t.Error("leaf certificate must not be a CA")
	}
}

func TestNewLeafSignedByFreshCA(t *testing.T) {
	// The "new" subcommand passes no template to the CA generator, so the CA
	// must get the default subject rather than an empty one.
	caCert, caKey, err := generateCARoot(nil)
	if err != nil {
		t.Fatalf("generateCARoot(nil): %v", err)
	}
	if caCert.Subject.CommonName == "" {
		t.Fatal("generated CA has an empty CommonName")
	}

	cert := newLeaf(t, "localhost", caCert, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		for _, name := range []string{"localhost", "127.0.0.1"} {
			_, err := cert.Verify(x509.VerifyOptions{
				DNSName:   name,
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{eku},
			})
			if err != nil {
				t.Errorf("verify %q for %v against fresh CA: %v", name, eku, err)
			}
		}
	}
}

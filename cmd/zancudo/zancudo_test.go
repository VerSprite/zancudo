package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func pemBlock(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// must unwraps the result of a marshalling call that cannot fail for the
// freshly generated keys used in these tests.
func must(der []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return der
}

// selfSignedCertPEM wraps the public half of priv in a minimal self-signed certificate.
func selfSignedCertPEM(t *testing.T, priv crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jwt-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	return pemBlock(t, "CERTIFICATE", must(der, err))
}

func signToken(t *testing.T, method jwt.SigningMethod, key crypto.PrivateKey) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, jwt.MapClaims{"sub": "device-42"}).SignedString(key)
	if err != nil {
		t.Fatalf("signing %s token: %v", method.Alg(), err)
	}
	return token
}

func TestLoadJWTKeyAcceptsPublicPrivateAndCertificate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaToken := signToken(t, jwt.SigningMethodRS256, rsaKey)
	ecToken := signToken(t, jwt.SigningMethodES256, ecKey)
	edToken := signToken(t, jwt.SigningMethodEdDSA, edPriv)

	ecSEC1 := pemBlock(t, "EC PRIVATE KEY", must(x509.MarshalECPrivateKey(ecKey)))
	// "openssl ecparam -genkey" writes the curve parameters before the key.
	ecParams := pemBlock(t, "EC PARAMETERS", must([]byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil))

	tests := []struct {
		name  string
		pem   []byte
		token string
	}{
		{"RSA PKCS#1 private", pemBlock(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), rsaToken},
		{"RSA PKCS#8 private", pemBlock(t, "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(rsaKey))), rsaToken},
		{"RSA PKIX public", pemBlock(t, "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&rsaKey.PublicKey))), rsaToken},
		{"RSA PKCS#1 public", pemBlock(t, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)), rsaToken},
		{"RSA certificate", selfSignedCertPEM(t, rsaKey), rsaToken},
		{"EC SEC1 private", ecSEC1, ecToken},
		{"EC SEC1 private after EC PARAMETERS", append(ecParams, ecSEC1...), ecToken},
		{"EC PKCS#8 private", pemBlock(t, "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(ecKey))), ecToken},
		{"EC PKIX public", pemBlock(t, "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&ecKey.PublicKey))), ecToken},
		{"EC certificate", selfSignedCertPEM(t, ecKey), ecToken},
		{"Ed25519 PKCS#8 private", pemBlock(t, "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(edPriv))), edToken},
		{"Ed25519 PKIX public", pemBlock(t, "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(edPub))), edToken},
		{"Ed25519 certificate", selfSignedCertPEM(t, edPriv), edToken},
	}
	for _, tt := range tests {
		key, err := loadJWTKey(tt.pem)
		if err != nil {
			t.Errorf("%s: loadJWTKey: %v", tt.name, err)
			continue
		}
		if err := verifyJWTSignature(tt.token, key); err != nil {
			t.Errorf("%s: token did not verify: %v", tt.name, err)
		}
	}
}

func TestLoadJWTKeyRejectsUnusableInput(t *testing.T) {
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"not PEM", []byte("definitely not a key")},
		{"garbage PEM", pemBlock(t, "PUBLIC KEY", []byte("garbage"))},
		{"unsupported key type (X25519)", pemBlock(t, "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(x25519.PublicKey())))},
	}
	for _, tt := range tests {
		if key, err := loadJWTKey(tt.data); err == nil {
			t.Errorf("%s: loadJWTKey returned %T, want error", tt.name, key)
		}
	}
}

func TestVerifyJWTSignatureRejectsWrongKey(t *testing.T) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, jwt.SigningMethodRS256, signer)

	if err := verifyJWTSignature(token, &other.PublicKey); err == nil {
		t.Error("token verified with an unrelated RSA key")
	}
	if err := verifyJWTSignature(token, &ecKey.PublicKey); err == nil {
		t.Error("RS256 token verified with an ECDSA key")
	}
}

func TestLoadJWTKeysKeepsEachKeyWithItsOwnPath(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.pem")
	bad := filepath.Join(dir, "bad.pem")
	good := filepath.Join(dir, "good.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodPEM := pemBlock(t, "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&ecKey.PublicKey)))
	if err := os.WriteFile(good, goodPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keys := loadJWTKeys([]string{missing, bad, good})

	if len(keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(keys))
	}
	if keys[0].path != good {
		t.Errorf("key labelled %q, want %q", keys[0].path, good)
	}
	token := signToken(t, jwt.SigningMethodES256, ecKey)
	if err := verifyJWTSignature(token, keys[0].key); err != nil {
		t.Errorf("loaded key does not verify its token: %v", err)
	}
}

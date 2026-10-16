package verifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
)

func TestValidateEKKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	critical := []pkix.Extension{{Id: keyUsageOID, Critical: true}}
	for name, test := range map[string]struct {
		certificate *x509.Certificate
		want        string
	}{
		"P-256 with key agreement": {
			certificate: &x509.Certificate{
				PublicKey:  &ecKey.PublicKey,
				KeyUsage:   x509.KeyUsageKeyAgreement,
				Extensions: critical,
			},
		},
		"RSA 2048 with key encipherment": {
			certificate: &x509.Certificate{
				PublicKey:  &rsaKey.PublicKey,
				KeyUsage:   x509.KeyUsageKeyEncipherment,
				Extensions: critical,
			},
		},
		"P-256 without key agreement": {
			certificate: &x509.Certificate{
				PublicKey:  &ecKey.PublicKey,
				KeyUsage:   x509.KeyUsageKeyEncipherment,
				Extensions: critical,
			},
			want: "ECC endorsement certificate does not permit key agreement",
		},
		"RSA 2048 without key encipherment": {
			certificate: &x509.Certificate{
				PublicKey:  &rsaKey.PublicKey,
				KeyUsage:   x509.KeyUsageKeyAgreement,
				Extensions: critical,
			},
			want: "RSA endorsement certificate does not permit key encipherment",
		},
		"no Key Usage extension": {
			certificate: &x509.Certificate{
				PublicKey: &ecKey.PublicKey,
				KeyUsage:  x509.KeyUsageKeyAgreement,
			},
			want: "lacks a Key Usage extension",
		},
		"non-critical Key Usage extension": {
			certificate: &x509.Certificate{
				PublicKey:  &ecKey.PublicKey,
				KeyUsage:   x509.KeyUsageKeyAgreement,
				Extensions: []pkix.Extension{{Id: keyUsageOID}},
			},
			want: "non-critical Key Usage extension",
		},
		"RSA below 2048 bits": {
			certificate: &x509.Certificate{
				PublicKey:  &rsa.PublicKey{N: big.NewInt(0).Lsh(big.NewInt(1), 1023), E: 65537},
				Extensions: critical,
			},
			want: "RSA endorsement key is only 1024 bits",
		},
		"ECC below 256 bits": {
			certificate: &x509.Certificate{
				PublicKey:  &ecdsa.PublicKey{Curve: elliptic.P224()},
				Extensions: critical,
			},
			want: "ECC endorsement key is smaller than 256 bits",
		},
		"ECC without a curve": {
			certificate: &x509.Certificate{PublicKey: &ecdsa.PublicKey{}, Extensions: critical},
			want:        "ECC endorsement key is smaller than 256 bits",
		},
		"unsupported key type": {
			certificate: &x509.Certificate{
				PublicKey:  ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)),
				Extensions: critical,
			},
			want: "unsupported endorsement key type",
		},
		"no key at all": {
			certificate: &x509.Certificate{Extensions: critical},
			want:        "unsupported endorsement key type",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateEKKey(test.certificate)
			if test.want == "" {
				if err != nil {
					t.Fatalf("permitted endorsement key rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

package verifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"testing"
	"time"
)

func TestBundledNuvotonCertificates(t *testing.T) {
	for _, bundle := range []struct {
		name         string
		pem          []byte
		fingerprints []string
		pool         *x509.CertPool
		verify       func(*x509.Certificate) error
	}{
		{
			name: "roots",
			pem:  nuvotonRootPEM,
			pool: nuvotonTrust.roots,
			fingerprints: []string{
				"2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54",
				"e38c280f7c0e0b49f31efc7531032bb6a86c3fba4eb89beb1d510eaa4510ae4a",
				"ba70a6ea7b77c7fee8947a07b1e70e0b26d39ce5e6307f63d5e4b9507f19a157",
				"4aebe77a51ed29959a7f9f5e07a24a558dee8167f3985d724995a541c258dfda",
				"cd8185ff8995ed09811970090a8c36fafab34ef87f47fa51fdb9ecf95c9c2e04",
				"66e3a1013d4f697700f731e7d68c69b58351f90ec9580d85862d020ab4abf1af",
				"083e7bd13e8fe0bb9b0c64db9e0c8356681df65714d2d5c4925eb98ae1369d40",
				"fc61abbc18100f460205ebe09d8c3e6995ac2be2234344a7facb62e15f9a7584",
				"2bbc5db224b8f28a6d2cf336d4da7ab21c8c490e3d60ef497801dc0b6ac00227",
			},
			verify: func(certificate *x509.Certificate) error {
				return certificate.CheckSignatureFrom(certificate)
			},
		},
		{
			name: "intermediates",
			pem:  nuvotonIntermediatePEM,
			pool: nuvotonTrust.intermediates,
			fingerprints: []string{
				"bf4cd3d1224b5d3f954991992ef30f91a34f7a880fabae75ad10184594ddf42b",
				"30dd089c936d158c4515fb5cf00e0ee3f8f5ea4bc7d4844d4dec6ef23d040fc8",
				"99517a0395f95ea8422abe75997f4be1107c0249749407f4fe1de3c1e5a43dcc",
				"aa9a1682088775b6c2558c89a891591713ee0f23adada04e17d001a7fbbd55d0",
			},
			verify: func(certificate *x509.Certificate) error {
				_, err := certificate.Verify(x509.VerifyOptions{
					Roots:       nuvotonTrust.roots,
					CurrentTime: time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC),
					KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				})
				return err
			},
		},
	} {
		t.Run(bundle.name, func(t *testing.T) {
			certificates := parseCertificateBundle(t, bundle.name, bundle.pem)
			var fingerprints []string
			expectedPool := x509.NewCertPool()
			for _, certificate := range certificates {
				sum := sha256.Sum256(certificate.Raw)
				fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
				expectedPool.AddCert(certificate)
				if err := bundle.verify(certificate); err != nil {
					t.Errorf("%s: %v", certificate.Subject, err)
				}
			}
			if !bundle.pool.Equal(expectedPool) {
				t.Fatalf("production Nuvoton %s pool differs from the bundled PEM", bundle.name)
			}
			slices.Sort(fingerprints)
			slices.Sort(bundle.fingerprints)
			if !slices.Equal(fingerprints, bundle.fingerprints) {
				t.Fatalf("bundled Nuvoton %s = %q, want %q", bundle.name, fingerprints, bundle.fingerprints)
			}
		})
	}
}

func parseCertificateBundle(
	t *testing.T,
	name string,
	pemBytes []byte,
) []*x509.Certificate {
	t.Helper()
	var certificates []*x509.Certificate
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("invalid PEM in bundled Nuvoton %s", name)
		}
		pemBytes = rest
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if !certificate.IsCA ||
			!slices.Contains(
				certificate.Subject.Organization,
				"Nuvoton Technology Corporation",
			) {
			t.Fatalf("unexpected Nuvoton CA %s", certificate.Subject)
		}
		certificates = append(certificates, certificate)
	}
	return certificates
}

const bundledCAWarningPeriod = 365 * 24 * time.Hour

func TestBundledCertificatesAreNotExpiring(t *testing.T) {
	now := time.Now()
	for _, bundle := range []struct {
		name string
		pem  []byte
	}{
		{"roots", nuvotonRootPEM},
		{"intermediates", nuvotonIntermediatePEM},
	} {
		for _, certificate := range parseCertificateBundle(t, bundle.name, bundle.pem) {
			if now.Before(certificate.NotBefore) {
				t.Errorf(
					"bundled %s %s is not valid until %s",
					bundle.name,
					certificate.Subject,
					certificate.NotBefore,
				)
			}
			if certificate.NotAfter.Sub(now) < bundledCAWarningPeriod {
				t.Errorf(
					"bundled %s %s expires %s, within the %s notice period",
					bundle.name,
					certificate.Subject,
					certificate.NotAfter,
					bundledCAWarningPeriod,
				)
			}
		}
	}
}

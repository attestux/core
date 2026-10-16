package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

type endorsementCertificateFixture struct {
	now          time.Time
	roots        *x509.CertPool
	root         *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	ekKey        *ecdsa.PrivateKey
	publicDER    []byte
	leafTemplate x509.Certificate
}

func TestValidateEndorsementsWithTrustAcceptsTheTCGSubjectAltName(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	candidate := fixture.issue(t, 2, nil)
	parsedLeaf, err := x509.ParseCertificate(candidate.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsedLeaf.Verify(x509.VerifyOptions{
		Roots:       fixture.roots,
		CurrentTime: fixture.now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("standard verification unexpectedly handled the TCG directoryName SAN")
	}
	if !slices.ContainsFunc(
		parsedLeaf.UnhandledCriticalExtensions,
		subjectAltNameOID.Equal,
	) {
		t.Fatal("fixture certificate lacks the unhandled critical SAN this test relies on")
	}

	validated, err := validateEndorsementsWithTrust(
		[]*attestuxv1.EndorsementKey{candidate},
		certificateTrust{roots: fixture.roots},
		fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	publicSum := sha256.Sum256(fixture.publicDER)
	if !bytes.Equal(validated.publicSHA256, publicSum[:]) {
		t.Fatal("validated endorsement has the wrong public-key fingerprint")
	}
}

func TestValidateEndorsementsWithTrustRequiresACandidate(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	for want, candidates := range map[string][]*attestuxv1.EndorsementKey{
		"no endorsement-key certificate supplied": nil,
		"missing endorsement key":                 {nil},
	} {
		validated, err := validateEndorsementsWithTrust(candidates, certificateTrust{roots: fixture.roots}, fixture.now)
		if validated != nil || err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("candidates %v returned %v, %v; want %q", candidates, validated, err, want)
		}
	}
}

func TestValidateEndorsementsWithTrustAcceptsANonCriticalSubjectAltName(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	candidate := fixture.issue(t, 4, func(template *x509.Certificate) {
		template.ExtraExtensions[0].Critical = false
	})
	if _, err := validateEndorsementsWithTrust(
		[]*attestuxv1.EndorsementKey{candidate},
		certificateTrust{roots: fixture.roots},
		fixture.now,
	); err != nil {
		t.Fatalf("rejected valid non-critical TCG SAN: %v", err)
	}
}

func TestValidateEndorsementsWithTrustThroughIntermediate(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(50),
		Subject:               pkix.Name{CommonName: "AttesTux Test Intermediate"},
		NotBefore:             fixture.now.Add(-time.Hour),
		NotAfter:              fixture.now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intermediateDER, err := x509.CreateCertificate(
		rand.Reader,
		intermediateTemplate,
		fixture.root,
		&intermediateKey.PublicKey,
		fixture.rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := fixture.leafTemplate
	leafTemplate.SerialNumber = big.NewInt(51)
	leafDER, err := x509.CreateCertificate(
		rand.Reader,
		&leafTemplate,
		intermediate,
		&fixture.ekKey.PublicKey,
		intermediateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &attestuxv1.EndorsementKey{
		PublicKey:   bytes.Clone(fixture.publicDER),
		Certificate: leafDER,
	}
	if _, err := validateEndorsementsWithTrust(
		[]*attestuxv1.EndorsementKey{candidate},
		certificateTrust{roots: fixture.roots},
		fixture.now,
	); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("certificate verified without its intermediate: %v", err)
	}

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, err := validateEndorsementsWithTrust(
		[]*attestuxv1.EndorsementKey{candidate},
		certificateTrust{
			roots:         fixture.roots,
			intermediates: intermediates,
		},
		fixture.now,
	); err != nil {
		t.Fatalf("certificate did not verify through its intermediate: %v", err)
	}
}

func TestValidateEndorsementsWithTrustRejectsInvalidCertificates(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	weakKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPublic, err := x509.MarshalPKIXPublicKey(&wrongKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		roots           *x509.CertPool
		now             time.Time
		changeTemplate  func(*x509.Certificate)
		changeCandidate func(*attestuxv1.EndorsementKey)
		public          crypto.PublicKey
		wantError       string
	}{
		{
			name:      "weak ECC endorsement key",
			public:    &weakKey.PublicKey,
			wantError: "ECC endorsement key is smaller than 256 bits",
		},
		{
			name: "CA certificate used as EK leaf",
			changeTemplate: func(template *x509.Certificate) {
				template.IsCA = true
				template.BasicConstraintsValid = true
			},
			wantError: "endorsement certificate is a CA certificate",
		},
		{
			name: "missing key usage",
			changeTemplate: func(template *x509.Certificate) {
				template.KeyUsage = 0
			},
			wantError: "lacks a Key Usage extension",
		},
		{
			name: "wrong ECC key usage",
			changeTemplate: func(template *x509.Certificate) {
				template.KeyUsage = x509.KeyUsageDigitalSignature
			},
			wantError: "does not permit key agreement",
		},
		{
			name: "missing EK purpose",
			changeTemplate: func(template *x509.Certificate) {
				template.UnknownExtKeyUsage = nil
			},
			wantError: "lacks EK credential purpose",
		},
		{
			name: "wrong public key",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.PublicKey = wrongPublic
			},
			wantError: "does not match the TPM EK",
		},
		{
			name: "public key with trailing data",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.PublicKey = append(candidate.PublicKey, 0)
			},
			wantError: "does not match the TPM EK",
		},
		{
			name: "empty public key",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.PublicKey = nil
			},
			wantError: "invalid endorsement public-key size",
		},
		{
			name: "oversized public key",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.PublicKey = make([]byte, maxEKPublicSize+1)
			},
			wantError: "invalid endorsement public-key size",
		},
		{
			name: "empty certificate",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.Certificate = nil
			},
			wantError: "invalid endorsement certificate size",
		},
		{
			name: "oversized certificate",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.Certificate = make([]byte, maxEKCertificateSize+1)
			},
			wantError: "invalid endorsement certificate size",
		},
		{
			name: "malformed certificate",
			changeCandidate: func(candidate *attestuxv1.EndorsementKey) {
				candidate.Certificate = []byte{0xff}
			},
			wantError: "parse endorsement certificate",
		},
		{
			name: "missing SAN",
			changeTemplate: func(template *x509.Certificate) {
				template.ExtraExtensions = nil
			},
			wantError: "lacks a SAN extension",
		},
		{
			name: "empty subject with non-critical SAN",
			changeTemplate: func(template *x509.Certificate) {
				template.Subject = pkix.Name{}
				template.ExtraExtensions[0].Critical = false
			},
			wantError: "empty subject has a non-critical SAN",
		},
		{
			name: "missing TPM model",
			changeTemplate: func(template *x509.Certificate) {
				template.ExtraExtensions = []pkix.Extension{
					marshalTCGSubjectAltName(t, []pkix.AttributeTypeAndValue{
						{Type: tpmManufacturerNameOID, Value: "swtpm"},
						{Type: tpmVersionNameOID, Value: "2.0"},
					}),
				}
			},
			wantError: "lacks required attribute 2.23.133.2.2",
		},
		{
			name: "malformed TCG SAN",
			changeTemplate: func(template *x509.Certificate) {
				template.ExtraExtensions = []pkix.Extension{{
					Id:       subjectAltNameOID,
					Critical: true,
					Value:    []byte{0x30, 0x03, 0xa4, 0x01, 0x00},
				}}
			},
			wantError: "parse subject alternative name",
		},
		{
			name: "unknown critical extension",
			changeTemplate: func(template *x509.Certificate) {
				template.ExtraExtensions = append(
					template.ExtraExtensions,
					pkix.Extension{
						Id:       asn1.ObjectIdentifier{1, 2, 3, 4},
						Critical: true,
						Value:    []byte{asn1.TagNull, 0},
					},
				)
			},
			wantError: "unhandled critical extension",
		},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			public := test.public
			if public == nil {
				public = &fixture.ekKey.PublicKey
			}
			candidate := fixture.issueFor(t, int64(index+4), public, test.changeTemplate)
			if test.changeCandidate != nil {
				test.changeCandidate(candidate)
			}
			roots := test.roots
			if roots == nil {
				roots = fixture.roots
			}
			now := test.now
			if now.IsZero() {
				now = fixture.now
			}
			_, err := validateEndorsementsWithTrust(
				[]*attestuxv1.EndorsementKey{candidate},
				certificateTrust{roots: roots},
				now,
			)
			if err == nil {
				t.Fatal("accepted invalid endorsement certificate")
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error %q does not contain %q", err, test.wantError)
			}
		})
	}
}

func newEndorsementCertificateFixture(
	t testing.TB,
) *endorsementCertificateFixture {
	t.Helper()

	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AttesTux Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader,
		rootTemplate,
		rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	return newEndorsementCertificateFixtureForRoot(t, root, rootKey, now)
}

func newEndorsementCertificateFixtureForRoot(
	t testing.TB,
	root *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
	now time.Time,
) *endorsementCertificateFixture {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &endorsementCertificateFixture{
		now:       now,
		roots:     roots,
		root:      root,
		rootKey:   rootKey,
		ekKey:     ekKey,
		publicDER: publicDER,
		leafTemplate: x509.Certificate{
			Subject:            pkix.Name{CommonName: "Test TPM EK"},
			NotBefore:          now.Add(-time.Hour),
			NotAfter:           now.Add(time.Hour),
			KeyUsage:           x509.KeyUsageKeyAgreement,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{ekCredentialOID},
			ExtraExtensions: []pkix.Extension{
				marshalTCGSubjectAltName(t, []pkix.AttributeTypeAndValue{
					{Type: tpmManufacturerNameOID, Value: "swtpm"},
					{Type: tpmModelNameOID, Value: "VM"},
					{Type: tpmVersionNameOID, Value: "2.0"},
				}),
			},
		},
	}
}

func (fixture *endorsementCertificateFixture) issue(
	t testing.TB,
	serial int64,
	changeTemplate func(*x509.Certificate),
) *attestuxv1.EndorsementKey {
	t.Helper()
	return fixture.issueFor(t, serial, &fixture.ekKey.PublicKey, changeTemplate)
}

func (fixture *endorsementCertificateFixture) issueFor(
	t testing.TB,
	serial int64,
	public crypto.PublicKey,
	changeTemplate func(*x509.Certificate),
) *attestuxv1.EndorsementKey {
	t.Helper()

	template := fixture.leafTemplate
	template.SerialNumber = big.NewInt(serial)
	template.ExtraExtensions = append(
		[]pkix.Extension(nil),
		template.ExtraExtensions...,
	)
	if _, isRSA := public.(*rsa.PublicKey); isRSA {
		template.KeyUsage = x509.KeyUsageKeyEncipherment
	}
	if changeTemplate != nil {
		changeTemplate(&template)
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		fixture.root,
		public,
		fixture.rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return &attestuxv1.EndorsementKey{
		PublicKey:   publicDER,
		Certificate: certificateDER,
	}
}

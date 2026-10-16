package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

type validatedEndorsement struct {
	publicKey    crypto.PublicKey
	publicSHA256 []byte
}

type certificateTrust struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

func validateEndorsementsWithTrust(
	candidates []*attestuxv1.EndorsementKey,
	trust certificateTrust,
	now time.Time,
) (*validatedEndorsement, error) {
	var failures []error
	for index, candidate := range candidates {
		validated, err := validateEndorsementWithTrust(candidate, trust, now)
		if err == nil {
			return validated, nil
		}
		failures = append(failures, fmt.Errorf("EK certificate %d: %w", index, err))
	}
	if len(failures) == 0 {
		return nil, errors.New("no endorsement-key certificate supplied")
	}
	return nil, errors.Join(failures...)
}

func validateEndorsementWithTrust(
	candidate *attestuxv1.EndorsementKey,
	trust certificateTrust,
	now time.Time,
) (*validatedEndorsement, error) {
	if candidate == nil {
		return nil, errors.New("missing endorsement key")
	}
	if len(candidate.PublicKey) == 0 || len(candidate.PublicKey) > maxEKPublicSize {
		return nil, errors.New("invalid endorsement public-key size")
	}
	if len(candidate.Certificate) == 0 ||
		len(candidate.Certificate) > maxEKCertificateSize {
		return nil, errors.New("invalid endorsement certificate size")
	}
	certificate, err := x509.ParseCertificate(candidate.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse endorsement certificate: %w", err)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil || !bytes.Equal(certificatePublic, candidate.PublicKey) {
		return nil, errors.New("endorsement certificate public key does not match the TPM EK")
	}
	if err := validateEKCertificateProfile(certificate); err != nil {
		return nil, err
	}
	if _, err := acceptTCGSubjectAltName(certificate).Verify(x509.VerifyOptions{
		Roots:         trust.roots,
		Intermediates: trust.intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("verify endorsement certificate: %w", err)
	}
	publicSum := sha256.Sum256(candidate.PublicKey)
	return &validatedEndorsement{
		publicKey:    certificate.PublicKey,
		publicSHA256: publicSum[:],
	}, nil
}

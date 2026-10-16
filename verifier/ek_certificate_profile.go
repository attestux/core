package verifier

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

var (
	ekCredentialOID = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	keyUsageOID     = asn1.ObjectIdentifier{2, 5, 29, 15}
)

func validateEKCertificateProfile(certificate *x509.Certificate) error {
	if certificate.IsCA {
		return errors.New("endorsement certificate is a CA certificate")
	}
	if err := validateEKKey(certificate); err != nil {
		return err
	}
	if !slices.ContainsFunc(certificate.UnknownExtKeyUsage, ekCredentialOID.Equal) {
		return fmt.Errorf(
			"endorsement certificate lacks EK credential purpose %s",
			ekCredentialOID,
		)
	}
	return validateEKCertificateSubjectAltName(certificate)
}

// TCG requires storage/decryption Key Usage, with a different bit for each algorithm.
func validateEKKey(certificate *x509.Certificate) error {
	// crypto/x509 rejects duplicate extensions, so the first match is the only one.
	index := slices.IndexFunc(certificate.Extensions, func(extension pkix.Extension) bool {
		return extension.Id.Equal(keyUsageOID)
	})
	if index < 0 {
		return errors.New("endorsement certificate lacks a Key Usage extension")
	}
	if !certificate.Extensions[index].Critical {
		return errors.New("endorsement certificate has a non-critical Key Usage extension")
	}
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA endorsement key is only %d bits", key.N.BitLen())
		}
		if certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return errors.New("RSA endorsement certificate does not permit key encipherment")
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return errors.New("ECC endorsement key is smaller than 256 bits")
		}
		if certificate.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return errors.New("ECC endorsement certificate does not permit key agreement")
		}
	default:
		return fmt.Errorf("unsupported endorsement key type %T", key)
	}
	return nil
}

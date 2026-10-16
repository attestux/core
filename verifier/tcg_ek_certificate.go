package verifier

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"

	attestationx509 "github.com/google/go-attestation/x509"
)

const maxTPMNameLength = 256

var (
	subjectAltNameOID      = asn1.ObjectIdentifier{2, 5, 29, 17}
	tpmManufacturerNameOID = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tpmModelNameOID        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tpmVersionNameOID      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	requiredTPMNameOIDs    = []asn1.ObjectIdentifier{
		tpmManufacturerNameOID,
		tpmModelNameOID,
		tpmVersionNameOID,
	}
)

// crypto/x509 doesn't parse TCG's directoryName SAN, so we check it here.
func validateEKCertificateSubjectAltName(certificate *x509.Certificate) error {
	index := slices.IndexFunc(certificate.Extensions, func(extension pkix.Extension) bool {
		return extension.Id.Equal(subjectAltNameOID)
	})
	if index < 0 {
		return errors.New("endorsement certificate lacks a SAN extension")
	}
	subjectAltName := certificate.Extensions[index]
	if len(certificate.Subject.Names) == 0 && !subjectAltName.Critical {
		return errors.New(
			"endorsement certificate with an empty subject has a non-critical SAN",
		)
	}
	if err := validateTCGEKSubjectAltName(subjectAltName); err != nil {
		return fmt.Errorf("validate TCG EK certificate SAN: %w", err)
	}
	return nil
}

// acceptTCGSubjectAltName returns a certificate that chain verification won't
// reject for the validated SAN. Call it only after validateEKCertificateProfile.
func acceptTCGSubjectAltName(certificate *x509.Certificate) *x509.Certificate {
	if !slices.ContainsFunc(
		certificate.UnhandledCriticalExtensions,
		subjectAltNameOID.Equal,
	) {
		return certificate
	}
	clone := *certificate
	clone.UnhandledCriticalExtensions = slices.DeleteFunc(
		slices.Clone(certificate.UnhandledCriticalExtensions),
		subjectAltNameOID.Equal,
	)
	return &clone
}

func validateTCGEKSubjectAltName(extension pkix.Extension) error {
	subjectAltName, err := attestationx509.ParseSubjectAltName(extension)
	if err != nil {
		return fmt.Errorf("parse subject alternative name: %w", err)
	}
	if len(subjectAltName.DirectoryNames) != 1 ||
		len(subjectAltName.PermanentIdentifiers) != 0 {
		return errors.New("SAN must contain exactly one directoryName")
	}

	found := make(map[string]bool, len(requiredTPMNameOIDs))
	for _, attribute := range subjectAltName.DirectoryNames[0].Names {
		if !slices.ContainsFunc(requiredTPMNameOIDs, attribute.Type.Equal) {
			return fmt.Errorf(
				"directoryName contains unsupported attribute %s",
				attribute.Type,
			)
		}
		key := attribute.Type.String()
		if found[key] {
			return fmt.Errorf("directoryName repeats attribute %s", attribute.Type)
		}
		value, ok := attribute.Value.(string)
		if !ok || len(value) == 0 || len(value) > maxTPMNameLength {
			return fmt.Errorf(
				"directoryName attribute %s must be a nonempty string of at most %d bytes",
				attribute.Type,
				maxTPMNameLength,
			)
		}
		found[key] = true
	}

	for _, oid := range requiredTPMNameOIDs {
		if !found[oid.String()] {
			return fmt.Errorf("directoryName lacks required attribute %s", oid)
		}
	}
	return nil
}

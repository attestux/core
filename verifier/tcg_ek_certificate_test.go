package verifier

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"

	attestationx509 "github.com/google/go-attestation/x509"
)

const swtpmCertSubjectAltNameHex = "3035a43330313110300e06056781050201" +
	"0c05737774706d310d300b060567810502020c02564d310e300c060567810502" +
	"030c03322e30"

func TestValidateTCGEKSubjectAltName(t *testing.T) {
	extension := pkix.Extension{
		Id:       subjectAltNameOID,
		Critical: true,
		Value:    swtpmCertSubjectAltName(t),
	}
	if err := validateTCGEKSubjectAltName(extension); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTCGEKSubjectAltNamePolicy(t *testing.T) {
	valid := []pkix.AttributeTypeAndValue{
		{Type: tpmManufacturerNameOID, Value: printableString("manufacturer")},
		{Type: tpmModelNameOID, Value: printableString("model")},
		{Type: tpmVersionNameOID, Value: printableString("version")},
	}
	tests := []struct {
		name           string
		directoryNames [][]pkix.AttributeTypeAndValue
		wantError      string
	}{
		{
			name:           "printable strings",
			directoryNames: [][]pkix.AttributeTypeAndValue{valid},
		},
		{
			name: "missing attribute",
			directoryNames: [][]pkix.AttributeTypeAndValue{{
				{Type: tpmManufacturerNameOID, Value: "manufacturer"},
				{Type: tpmVersionNameOID, Value: "version"},
			}},
			wantError: "lacks required attribute 2.23.133.2.2",
		},
		{
			name: "duplicate attribute",
			directoryNames: [][]pkix.AttributeTypeAndValue{append(
				append([]pkix.AttributeTypeAndValue(nil), valid...),
				pkix.AttributeTypeAndValue{
					Type: tpmModelNameOID, Value: "duplicate",
				},
			)},
			wantError: "repeats attribute 2.23.133.2.2",
		},
		{
			name: "unknown attribute",
			directoryNames: [][]pkix.AttributeTypeAndValue{append(
				append([]pkix.AttributeTypeAndValue(nil), valid...),
				pkix.AttributeTypeAndValue{
					Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "unknown",
				},
			)},
			wantError: "unsupported attribute 1.2.3.4",
		},
		{
			name: "empty value",
			directoryNames: [][]pkix.AttributeTypeAndValue{{
				{Type: tpmManufacturerNameOID, Value: ""},
				{Type: tpmModelNameOID, Value: "model"},
				{Type: tpmVersionNameOID, Value: "version"},
			}},
			wantError: "must be a nonempty string",
		},
		{
			name: "oversized value",
			directoryNames: [][]pkix.AttributeTypeAndValue{{
				{Type: tpmManufacturerNameOID, Value: strings.Repeat("x", 257)},
				{Type: tpmModelNameOID, Value: "model"},
				{Type: tpmVersionNameOID, Value: "version"},
			}},
			wantError: "at most 256 bytes",
		},
		{
			name: "non-string value",
			directoryNames: [][]pkix.AttributeTypeAndValue{{
				{Type: tpmManufacturerNameOID, Value: 42},
				{Type: tpmModelNameOID, Value: "model"},
				{Type: tpmVersionNameOID, Value: "version"},
			}},
			wantError: "must be a nonempty string",
		},
		{
			name:      "no directory name",
			wantError: "must contain exactly one directoryName",
		},
		{
			name:           "multiple directory names",
			directoryNames: [][]pkix.AttributeTypeAndValue{valid, valid},
			wantError:      "must contain exactly one directoryName",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extension := marshalTCGSubjectAltName(t, test.directoryNames...)
			err := validateTCGEKSubjectAltName(extension)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("got error %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateTCGEKSubjectAltNameRejectsAnAdditionalGeneralName(t *testing.T) {
	extension, err := attestationx509.MarshalSubjectAltName(
		&attestationx509.SubjectAltName{
			DirectoryNames: []pkix.Name{{
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: tpmManufacturerNameOID, Value: "manufacturer"},
					{Type: tpmModelNameOID, Value: "model"},
					{Type: tpmVersionNameOID, Value: "version"},
				},
			}},
			PermanentIdentifiers: []attestationx509.PermanentIdentifier{{
				IdentifierValue: "additional-name",
			}},
		},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = validateTCGEKSubjectAltName(extension)
	if err == nil || !strings.Contains(
		err.Error(),
		"must contain exactly one directoryName",
	) {
		t.Fatalf("got error %v, want exactly-one-directoryName rejection", err)
	}
}

func printableString(value string) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagPrintableString,
		Bytes: []byte(value),
	}
}

func FuzzValidateTCGEKSubjectAltName(f *testing.F) {
	f.Add(swtpmCertSubjectAltName(f))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, der []byte) {
		if len(der) <= maxEKCertificateSize {
			_ = validateTCGEKSubjectAltName(pkix.Extension{
				Id:       subjectAltNameOID,
				Critical: true,
				Value:    der,
			})
		}
	})
}

func swtpmCertSubjectAltName(t testing.TB) []byte {
	t.Helper()
	der, err := hex.DecodeString(swtpmCertSubjectAltNameHex)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

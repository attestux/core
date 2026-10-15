package attestation

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

var ErrNonCanonicalAKPublic = errors.New(
	"TPM public area contains trailing or non-canonical data",
)

// DeviceID hashes the canonical TPM public area. V1 requires SHA-256 Names and signatures.
func DeviceID(akPublic []byte) (string, error) {
	_, canonical, exactEncoding, err := ParseCanonicalAKPublic(akPublic)
	if err != nil {
		return "", err
	}
	if !exactEncoding {
		return "", ErrNonCanonicalAKPublic
	}
	return DeriveDeviceID(canonical), nil
}

func DeriveDeviceID(canonicalAKPublic []byte) string {
	sum := sha256.Sum256(canonicalAKPublic)
	return hex.EncodeToString(sum[:])
}

func ParseCanonicalAKPublic(raw []byte) (*attest.AKPublic, []byte, bool, error) {
	public, err := legacytpm2.DecodePublic(raw)
	if err != nil {
		return nil, nil, false, err
	}
	canonical, err := public.Encode()
	if err != nil {
		return nil, nil, false, fmt.Errorf("encode canonical TPM public area: %w", err)
	}
	ak, err := attest.ParseAKPublic(canonical)
	if err != nil {
		return nil, nil, false, err
	}
	if public.NameAlg != legacytpm2.AlgSHA256 {
		return nil, nil, false, fmt.Errorf(
			"attestation key TPM Name uses %s; SHA-256 is required",
			HashAlgorithmName(uint32(public.NameAlg)),
		)
	}
	if ak.Hash != crypto.SHA256 {
		return nil, nil, false, fmt.Errorf(
			"attestation key signatures use %s; SHA-256 is required",
			ak.Hash,
		)
	}
	return ak, canonical, bytes.Equal(raw, canonical), nil
}

// RequireSHA256SignatureEncoding checks the encoding only. The caller verifies the signature.
func RequireSHA256SignatureEncoding(encoded []byte) error {
	buffer := bytes.NewBuffer(encoded)
	signature, err := legacytpm2.DecodeSignature(buffer)
	if err != nil {
		return fmt.Errorf("decode TPM signature: %w", err)
	}
	if buffer.Len() != 0 {
		return errors.New("TPM signature contains trailing data")
	}
	var hash legacytpm2.Algorithm
	switch {
	case signature.RSA != nil:
		hash = signature.RSA.HashAlg
	case signature.ECC != nil:
		hash = signature.ECC.HashAlg
	default:
		return errors.New("TPM signature has no supported signature value")
	}
	if hash != legacytpm2.AlgSHA256 {
		return fmt.Errorf(
			"TPM signature uses %s; SHA-256 is required",
			HashAlgorithmName(uint32(hash)),
		)
	}
	return nil
}

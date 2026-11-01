package attestation

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func EncodeAndHashEndorsementPublic(public crypto.PublicKey) ([]byte, [sha256.Size]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("encode endorsement public key: %w", err)
	}
	return encoded, sha256.Sum256(encoded), nil
}

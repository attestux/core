package attestation

import (
	"crypto/sha256"

	"github.com/attestux/protocol-go/attestux/v1"
)

const ProtocolVersion = 1

func NewChallenge() *attestuxv1.AttestationChallenge {
	return &attestuxv1.AttestationChallenge{ProtocolVersion: ProtocolVersion}
}

// ActivationQuoteNonce is the only representation of the recovered secret sent
// back to the verifier. TPM quotes expose their extraData in clear text.
func ActivationQuoteNonce(secret []byte) []byte {
	digest := sha256.Sum256(secret)
	return digest[:]
}

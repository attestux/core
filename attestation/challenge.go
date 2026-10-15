package attestation

import (
	"crypto/rand"
	"fmt"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

func ValidateChallengeNonce(nonce []byte) error {
	if len(nonce) < minNonceSize || len(nonce) > MaxNonceSize {
		return fmt.Errorf(
			"nonce size %d is outside the permitted range of %d to %d bytes",
			len(nonce),
			minNonceSize,
			MaxNonceSize,
		)
	}
	return nil
}

func NewChallenge() *attestuxv1.AttestationChallenge {
	nonce := make([]byte, MaxNonceSize)
	rand.Read(nonce)
	return &attestuxv1.AttestationChallenge{Nonce: nonce}
}

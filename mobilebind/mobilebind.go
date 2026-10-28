// Package mobilebind exposes the narrow API supported by gomobile.
package mobilebind

import (
	"errors"
	"sync"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/verifier"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

type verificationSession interface {
	Report() *attestuxv1.VerificationReport
	ActivationChallenge() *attestuxv1.CredentialActivationChallenge
	CompleteActivationBytes([]byte) (*attestuxv1.VerificationReport, error)
	RejectActivation() (*attestuxv1.VerificationReport, error)
	Cancel()
}

// Verifier owns one activation session. Create and close one for each Android channel.
type Verifier struct {
	mu      sync.Mutex
	nonce   []byte
	session verificationSession
	closed  bool
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

// Only accept evidence for the nonce this verifier sent.
func (v *Verifier) IssueChallenge() ([]byte, error) {
	challenge := attestation.NewChallenge()
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("verifier is closed")
	}
	if v.nonce != nil {
		return nil, errors.New("verifier has already issued an attestation challenge")
	}
	v.nonce = challenge.Nonce
	return raw, nil
}

// PrepareVerification checks evidence and returns an activation challenge.
// The secret stays in this verifier.
func (v *Verifier) PrepareVerification(evidence []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("verifier is closed")
	}
	if v.session != nil {
		return nil, errors.New("verifier has already been used")
	}
	if v.nonce == nil {
		return nil, errors.New("verifier has not issued an attestation challenge")
	}
	session, err := verifier.PrepareVerification(evidence, v.nonce)
	if err != nil {
		return nil, err
	}
	v.session = session
	return encodePreparationOrCancel(session)
}

func encodePreparationOrCancel(session verificationSession) ([]byte, error) {
	report := session.Report()
	challenge := session.ActivationChallenge()
	raw, err := marshalPreparation(report, challenge)
	if challenge == nil || err != nil {
		session.Cancel()
	}
	return raw, err
}

func (v *Verifier) CompleteActivation(responseBytes []byte) ([]byte, error) {
	return v.complete(func(session verificationSession) (*attestuxv1.VerificationReport, error) {
		return session.CompleteActivationBytes(responseBytes)
	})
}

func (v *Verifier) RejectActivation() ([]byte, error) {
	return v.complete(verificationSession.RejectActivation)
}

func (v *Verifier) complete(
	complete func(verificationSession) (*attestuxv1.VerificationReport, error),
) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("verifier is closed")
	}
	if v.session == nil {
		return nil, errors.New("verifier has no verification session")
	}
	report, err := complete(v.session)
	if err != nil {
		return nil, err
	}
	return marshalCompletion(report)
}

// Close cancels the session. The verifier can't be reused afterward.
func (v *Verifier) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return
	}
	v.closed = true
	v.nonce = nil
	if v.session != nil {
		v.session.Cancel()
	}
}

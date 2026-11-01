// Package mobilebind exposes the narrow API supported by gomobile.
package mobilebind

import (
	"errors"
	"sync"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/verifier"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

type verificationSession interface {
	Report() *resultv1.VerificationReport
	ActivationChallenge() *attestuxv1.CredentialActivationChallenge
	CompleteEvidence([]byte) (*resultv1.VerificationReport, error)
	RejectActivation() (*resultv1.VerificationReport, error)
	RejectEvidence() (*resultv1.VerificationReport, error)
	Cancel()
}

// Verifier owns one activation session. Create and close one for each Android channel.
type Verifier struct {
	mu      sync.Mutex
	issued  bool
	session verificationSession
	closed  bool
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

// Begin key discovery; the secret challenge is generated after key validation.
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
	if v.issued {
		return nil, errors.New("verifier has already issued an attestation challenge")
	}
	v.issued = true
	return raw, nil
}

// PrepareVerification checks an encoded AttestationHello and returns an encrypted
// activation challenge, or a terminal completion if the hello is rejected.
// Only the hash of its secret remains in this verifier.
func (v *Verifier) PrepareVerification(hello []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, errors.New("verifier is closed")
	}
	if v.session != nil {
		return nil, errors.New("verifier has already been used")
	}
	if !v.issued {
		return nil, errors.New("verifier has not issued an attestation challenge")
	}
	session := verifier.PrepareVerification(hello)
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

func (v *Verifier) CompleteEvidence(evidenceBytes []byte) ([]byte, error) {
	return v.complete(func(session verificationSession) (*resultv1.VerificationReport, error) {
		return session.CompleteEvidence(evidenceBytes)
	})
}

func (v *Verifier) RejectActivation() ([]byte, error) {
	return v.complete(verificationSession.RejectActivation)
}

func (v *Verifier) RejectEvidence() ([]byte, error) {
	return v.complete(verificationSession.RejectEvidence)
}

func (v *Verifier) complete(
	complete func(verificationSession) (*resultv1.VerificationReport, error),
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
	if v.session != nil {
		v.session.Cancel()
	}
}

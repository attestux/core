package verifier

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
	"google.golang.org/protobuf/proto"
)

func TestCompleteActivationRequiresTheMatchingSecret(t *testing.T) {
	for _, tc := range []struct {
		name     string
		secret   func(expected []byte) []byte
		accepted bool
	}{
		{"correct", bytes.Clone, true},
		{"wrong same length", func(expected []byte) []byte {
			wrong := bytes.Clone(expected)
			wrong[0] ^= 0xff
			return wrong
		}, false},
		{"short", func(expected []byte) []byte { return bytes.Clone(expected[:len(expected)-1]) }, false},
		{"long", func(expected []byte) []byte { return append(bytes.Clone(expected), 0) }, false},
		{"missing", func([]byte) []byte { return nil }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := newActivationTestSession(t)
			secret := session.expectedSecret
			report, err := session.finishActivation(tc.secret(secret), "")
			if err != nil {
				t.Fatal(err)
			}
			want := attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED
			if tc.accepted {
				want = attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
			}
			if report.Status != want {
				t.Fatalf("status = %v, want %v", report.Status, want)
			}
			if !tc.accepted && (!containsMessage(report.Errors, "secret did not match") || describesTrust(report)) {
				t.Fatalf("rejected report %v; want the secret mismatch and no trust facts", report)
			}
			if tc.accepted && !describesTrust(report) {
				t.Fatalf("verified report %v names no trust policy", report)
			}
			requireActivationFinished(t, session, secret)
		})
	}
}

func TestPrepareVerificationChecksBothSignatureEncodings(t *testing.T) {
	for _, target := range []string{"quote", "creation"} {
		for _, mutation := range []string{"SHA-1", "trailing data"} {
			t.Run(target+"/"+mutation, func(t *testing.T) {
				nonce := make([]byte, 32)
				selection := allAttestedPCRs()
				e := newSoftwareAK(t).quoteEvidence(t, nonce, selection, zeroPCRComposite(selection))
				signature := bytes.Clone(e.PcrBanks[0].Quote.Signature)
				want := "TPM signature contains trailing data"
				if mutation == "SHA-1" {
					// TPMT_SIGNATURE starts with the signature algorithm and hash, both u16be.
					signature[2], signature[3] = 0, byte(attestation.TPMAlgSHA1)
					want = "TPM signature uses SHA-1; SHA-256 is required"
				} else {
					signature = append(signature, 0)
				}
				if target == "quote" {
					e.PcrBanks[0].Quote.Signature = signature
				} else {
					e.AkCreateSignature = signature
				}
				session, err := PrepareVerification(marshalEvidence(t, e), nonce)
				if err != nil {
					t.Fatal(err)
				}
				defer session.Cancel()
				report := session.Report()
				if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || !containsMessage(report.Errors, want) {
					t.Fatalf("unexpected report: %v", report)
				}
				if session.ActivationChallenge() != nil {
					t.Fatal("challenged evidence with invalid signature encoding")
				}
			})
		}
	}
}

func TestCompleteActivationFinishesOnceUnderConcurrentCalls(t *testing.T) {
	for range 4 {
		session := newActivationTestSession(t)
		secret := session.expectedSecret
		right := bytes.Clone(secret)
		wrong := bytes.Clone(right)
		wrong[0] ^= 0xff
		responses := make([][]byte, 2)
		for i, secret := range [][]byte{right, wrong} {
			var err error
			responses[i], err = proto.Marshal(&attestuxv1.CredentialActivationResponse{Secret: secret})
			if err != nil {
				t.Fatal(err)
			}
		}
		var (
			start                 = make(chan struct{})
			group                 sync.WaitGroup
			completions, verified atomic.Int32
		)
		for caller := range 16 {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				var (
					report *attestuxv1.VerificationReport
					err    error
				)
				switch caller % 5 {
				case 0:
					report, err = session.CompleteActivationBytes(responses[0])
				case 1:
					report, err = session.CompleteActivationBytes(responses[1])
				case 2:
					report, err = session.RejectActivation()
				case 3:
					report, err = session.CompleteActivationBytes([]byte{0xff})
				default:
					session.Report()
					session.ActivationChallenge()
					return
				}
				if err != nil {
					return
				}
				completions.Add(1)
				if report.Status == attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED {
					verified.Add(1)
					if caller%5 != 0 {
						t.Error("a call without the secret was verified")
					}
				}
			}()
		}
		close(start)
		group.Wait()
		final := session.Report()
		if completions.Load() != 1 ||
			(final.Status == attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED) != (verified.Load() == 1) {
			t.Fatalf("%d completions, %d verified, final status %v", completions.Load(), verified.Load(), final.Status)
		}
		requireActivationFinished(t, session, secret)
	}
}

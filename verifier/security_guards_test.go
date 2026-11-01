package verifier

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestVerificationIgnoresUnknownDiscoveryAndEvidenceFields(t *testing.T) {
	for _, target := range []string{"hello", "discovery", "evidence", "both"} {
		t.Run(target, func(t *testing.T) {
			fixture := newEndorsementCertificateFixture(t)
			ak := newSoftwareAK(t)
			evidence := softwareEvidenceWithFixture(t, fixture, ak)
			keys := proto.Clone(evidence.Keys).(*attestuxv1.AttestationKeys)
			unknown := protowire.AppendBytes(protowire.AppendTag(nil, 100, protowire.BytesType), []byte("future metadata"))
			if target == "discovery" || target == "both" {
				keys.ProtoReflect().SetUnknown(unknown)
				keys.EndorsementKeys[0].ProtoReflect().SetUnknown(unknown)
			}
			if target == "evidence" || target == "both" {
				evidence.ProtoReflect().SetUnknown(unknown)
				evidence.Keys.ProtoReflect().SetUnknown(unknown)
				evidence.Keys.EndorsementKeys[0].ProtoReflect().SetUnknown(unknown)
			}
			hello := &attestuxv1.AttestationHello{Keys: keys}
			if target == "hello" || target == "both" {
				hello.ProtoReflect().SetUnknown(unknown)
			}
			rawHello, err := proto.Marshal(hello)
			if err != nil {
				t.Fatal(err)
			}
			session := prepareVerificationWithPolicies(rawHello, []verificationPolicy{fixture.policy()}, fixture.now)
			defer session.Cancel()
			if session.ActivationChallenge() == nil {
				t.Fatalf("unknown fields rejected discovery: %v", session.Report())
			}
			if sum := sha256.Sum256(rawHello); !bytes.Equal(session.Report().EvidenceSha256, sum[:]) {
				t.Fatal("preparation did not hash the full raw hello")
			}
			// Preparation must own decoded fields even after the caller reuses its input buffer.
			clear(rawHello)
			nonce := session.expectedQuoteNonce
			raw := quoteResponse(t, ak, evidence, nonce)
			report, err := session.CompleteEvidence(raw)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(raw); report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED || !bytes.Equal(report.EvidenceSha256, sum[:]) {
				t.Fatalf("unknown fields broke verification or raw evidence retention: %v", report)
			}
			requireActivationFinished(t, session, nonce)
		})
	}
}

func TestCompleteEvidenceRequiresTheChallengedNonceAndKeys(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *VerificationSession, *softwareAK, *attestuxv1.AttestationEvidence) []byte
	}{
		// A software AK can forge creation proofs and quotes; without credential
		// activation for the certified EK, its quote cannot carry the required nonce.
		{"wrong hash", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			wrong := bytes.Clone(s.expectedQuoteNonce)
			wrong[0] ^= 0xff
			return quoteResponse(t, ak, e, wrong)
		}},
		{"missing hash", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			return quoteResponse(t, ak, e, nil)
		}},
		{"double hash", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			return quoteResponse(t, ak, e, attestation.ActivationQuoteNonce(s.expectedQuoteNonce))
		}},
		{"different AK", func(t *testing.T, s *VerificationSession, _ *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			other := newSoftwareAK(t)
			e.Keys.AttestationPublic = other.encodedPublic(t)
			return quoteResponse(t, other, e, s.expectedQuoteNonce)
		}},
		{"different EK", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			e.Keys.EndorsementKeys[0].Certificate[0] ^= 0xff
			return quoteResponse(t, ak, e, s.expectedQuoteNonce)
		}},
		{"forged signature", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			raw := quoteResponse(t, ak, e, s.expectedQuoteNonce)
			var out attestuxv1.AttestationEvidence
			if err := proto.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			out.PcrBanks[0].Quote.Signature[len(out.PcrBanks[0].Quote.Signature)-1] ^= 0xff
			return marshalEvidence(t, &out)
		}},
		{"hash without quote", func(t *testing.T, s *VerificationSession, ak *softwareAK, e *attestuxv1.AttestationEvidence) []byte {
			return bytes.Clone(s.expectedQuoteNonce)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, ak, e := newQuoteTestSession(t)
			// Only a verified quote may report this ignored bank.
			ignored := attestationtest.MakeUnsupportedPCRBank(e, attestation.TPMAlgSHA1, 20)
			ignored.Quote = &attestuxv1.Quote{Quote: []byte{1}, Signature: []byte{2}}
			e.PcrBanks = append(e.PcrBanks, ignored)
			nonce := session.expectedQuoteNonce
			report, err := session.CompleteEvidence(test.change(t, session, ak, e))
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || describesTrust(report) {
				t.Fatalf("invalid response verified: %v", report)
			}
			if report.DeviceId != "" || len(report.Pcrs)+len(report.Events)+len(report.Warnings) != 0 {
				t.Fatalf("invalid response exposed identity or quote results: %v", report)
			}
			requireActivationFinished(t, session, nonce)
		})
	}
}

func TestNonceMismatchDiagnosticsDoNotExposeNonces(t *testing.T) {
	for _, mutation := range []string{"wrong nonce", "nonce prefix", "missing nonce", "long nonce"} {
		t.Run(mutation, func(t *testing.T) {
			session, ak, evidence := newQuoteTestSession(t)
			defer session.Cancel()
			expected := session.expectedQuoteNonce
			received := bytes.Clone(expected)
			switch mutation {
			case "wrong nonce":
				received[0] ^= 0xff
			case "nonce prefix":
				received = received[:20]
			case "missing nonce":
				received = nil
			case "long nonce":
				received = append(received, 0)
			}
			report, err := session.CompleteEvidence(quoteResponse(t, ak, evidence, received))
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || report.DeviceId != "" || describesTrust(report) {
				t.Fatalf("nonce mismatch made trust claims: %v", report)
			}
			completion, err := CompletionForReport(report)
			if err != nil {
				t.Fatal(err)
			}
			for name, diagnostics := range map[string][]string{
				"report":       completion.Report.Errors,
				"receipt":      completion.Receipt.Errors,
				"saved report": session.Report().Errors,
			} {
				if len(diagnostics) != 1 || diagnostics[0] != "verify TPM quote: nonce mismatch" {
					t.Fatalf("%s must contain only the generic nonce-mismatch diagnostic: %q", name, diagnostics)
				}
			}
			requireActivationFinished(t, session, expected)
		})
	}
}

func TestVerificationValidatesQuoteAndCreationSignatureEncodings(t *testing.T) {
	for _, target := range []string{"quote", "creation"} {
		for _, mutation := range []string{"SHA-1", "trailing data"} {
			t.Run(target+"/"+mutation, func(t *testing.T) {
				session, ak, e := newQuoteTestSession(t)
				defer session.Cancel()
				raw := quoteResponse(t, ak, e, session.expectedQuoteNonce)
				if err := proto.Unmarshal(raw, e); err != nil {
					t.Fatal(err)
				}
				signature := bytes.Clone(e.PcrBanks[0].Quote.Signature)
				want := "TPM signature contains trailing data"
				if mutation == "SHA-1" {
					signature[2], signature[3] = 0, byte(attestation.TPMAlgSHA1)
					want = "TPM signature uses SHA-1; SHA-256 is required"
				} else {
					signature = append(signature, 0)
				}
				var report *resultv1.VerificationReport
				if target == "creation" {
					e.Keys.AkCreateSignature = signature
					fixture := newEndorsementCertificateFixture(t)
					rejected := prepareVerificationWithPolicies(marshalHello(t, e.Keys), []verificationPolicy{fixture.policy()}, fixture.now)
					report = rejected.Report()
				} else {
					e.PcrBanks[0].Quote.Signature = signature
					var err error
					report, err = session.CompleteEvidence(marshalEvidence(t, e))
					if err != nil {
						t.Fatal(err)
					}
				}
				if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || !containsMessage(report.Errors, want) {
					t.Fatalf("signature encoding accepted: %v", report)
				}
			})
		}
	}
}

func TestCompleteEvidenceFinishesOnceUnderConcurrentCalls(t *testing.T) {
	session, ak, e := newQuoteTestSession(t)
	nonce := session.expectedQuoteNonce
	right := quoteResponse(t, ak, e, nonce)
	wrong := quoteResponse(t, ak, e, bytes.Repeat([]byte{0x55}, 32))
	start := make(chan struct{})
	var group sync.WaitGroup
	var completions, verified atomic.Int32
	for caller := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			var report *resultv1.VerificationReport
			var err error
			switch caller % 5 {
			case 0:
				report, err = session.CompleteEvidence(right)
			case 1:
				report, err = session.CompleteEvidence(wrong)
			case 2:
				report, err = session.RejectActivation()
			case 3:
				report, err = session.CompleteEvidence([]byte{0xff})
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
					t.Error("a call without valid evidence verified")
				}
			}
		}()
	}
	close(start)
	group.Wait()
	if completions.Load() != 1 || (session.Report().Status == attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED) != (verified.Load() == 1) {
		t.Fatalf("completions=%d verified=%d", completions.Load(), verified.Load())
	}
	requireActivationFinished(t, session, nonce)
}

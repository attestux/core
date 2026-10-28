package mobilebind

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

type fakeVerificationSession struct {
	canceled            int
	report              *attestuxv1.VerificationReport
	activationChallenge *attestuxv1.CredentialActivationChallenge
	completeReport      *attestuxv1.VerificationReport
	completeErr         error
	activationResponses [][]byte
}

func (s *fakeVerificationSession) Report() *attestuxv1.VerificationReport {
	if s.report == nil {
		return &attestuxv1.VerificationReport{}
	}
	return s.report
}

func (s *fakeVerificationSession) ActivationChallenge() *attestuxv1.CredentialActivationChallenge {
	return s.activationChallenge
}

func (s *fakeVerificationSession) CompleteActivationBytes(response []byte) (*attestuxv1.VerificationReport, error) {
	s.activationResponses = append(s.activationResponses, bytes.Clone(response))
	return s.completeReport, s.completeErr
}

func (s *fakeVerificationSession) RejectActivation() (*attestuxv1.VerificationReport, error) {
	return s.completeReport, s.completeErr
}

func (s *fakeVerificationSession) Cancel() {
	s.canceled++
}

func pendingFakeSession() *fakeVerificationSession {
	return &fakeVerificationSession{
		report: &attestuxv1.VerificationReport{
			Status:         attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION,
			EvidenceSha256: make([]byte, sha256.Size),
		},
		activationChallenge: &attestuxv1.CredentialActivationChallenge{},
	}
}

func challengedVerifier(t *testing.T, verifier *Verifier) *Verifier {
	t.Helper()
	if _, err := verifier.IssueChallenge(); err != nil {
		t.Fatal(err)
	}
	return verifier
}

func decodePreparation(t *testing.T, raw []byte) *attestuxv1.VerificationPreparation {
	t.Helper()
	var preparation attestuxv1.VerificationPreparation
	if err := proto.Unmarshal(raw, &preparation); err != nil {
		t.Fatal(err)
	}
	return &preparation
}

func TestIssueChallengeCreatesOneFreshNonce(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	raw, err := verifier.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	var challenge attestuxv1.AttestationChallenge
	if err := proto.Unmarshal(raw, &challenge); err != nil {
		t.Fatal(err)
	}
	if len(challenge.Nonce) != 32 {
		t.Fatalf("issued nonce length = %d, want 32", len(challenge.Nonce))
	}
	if err := attestation.ValidateChallengeNonce(challenge.Nonce); err != nil {
		t.Fatalf("issued nonce is unusable: %v", err)
	}
	if _, err := verifier.IssueChallenge(); err == nil {
		t.Fatal("verifier issued a second challenge")
	}

	other := NewVerifier()
	defer other.Close()
	second, err := other.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, second) {
		t.Fatal("two verifiers issued the same challenge")
	}
}

func TestPrepareVerificationRequiresAnIssuedChallenge(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	if _, err := verifier.PrepareVerification([]byte{0xff}); err == nil {
		t.Fatal("verifier prepared evidence without issuing a challenge")
	}
}

func TestMalformedEvidenceProducesRetainableRejectedReport(t *testing.T) {
	verifier := challengedVerifier(t, NewVerifier())
	defer verifier.Close()
	evidence := []byte{0xff}
	raw, err := verifier.PrepareVerification(evidence)
	if err != nil {
		t.Fatal(err)
	}
	preparation := decodePreparation(t, raw)
	completion := preparation.GetCompletion()
	if completion == nil || preparation.GetPending() != nil {
		t.Fatalf("unexpected terminal preparation: %v", preparation)
	}
	sum := sha256.Sum256(evidence)
	report := completion.Report
	receipt := completion.Receipt
	if report == nil ||
		report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!bytes.Equal(report.EvidenceSha256, sum[:]) ||
		len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "malformed evidence") {
		t.Fatalf("unexpected malformed-evidence report: %v", report)
	}
	if receipt == nil ||
		receipt.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!bytes.Equal(receipt.EvidenceSha256, sum[:]) ||
		!slices.Equal(receipt.Errors, report.Errors) {
		t.Fatalf("unexpected malformed-evidence receipt: %v", receipt)
	}
	if _, err := verifier.PrepareVerification(evidence); err == nil {
		t.Fatal("single-use verifier accepted a second preparation")
	}
}

func TestEncodePreparationReturnsThePendingChallenge(t *testing.T) {
	session := pendingFakeSession()
	session.activationChallenge = &attestuxv1.CredentialActivationChallenge{
		EndorsementKeySha256: bytes.Repeat([]byte{3}, sha256.Size),
		Credential:           []byte{4},
		EncryptedSecret:      []byte{5},
	}
	raw, err := encodePreparationOrCancel(session)
	if err != nil {
		t.Fatal(err)
	}
	pending := decodePreparation(t, raw).GetPending()
	if pending == nil || pending.ActivationChallenge == nil ||
		pending.Report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION {
		t.Fatalf("unexpected preparation: %v", pending)
	}
	if !proto.Equal(pending.ActivationChallenge, session.activationChallenge) {
		t.Fatalf("activation challenge = %v, want %v", pending.ActivationChallenge, session.activationChallenge)
	}
	if session.canceled != 0 {
		t.Fatal("pending session was cancelled before activation")
	}
}

func TestEncodePreparationCancelsSessionsThatCannotBeActivated(t *testing.T) {
	for _, test := range []struct {
		name    string
		session *fakeVerificationSession
		encoded bool
	}{
		{"no challenge", &fakeVerificationSession{report: attestationtest.FailedReport()}, true},
		{"nonterminal report without a challenge", &fakeVerificationSession{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := encodePreparationOrCancel(test.session)
			if test.session.canceled != 1 {
				t.Fatalf("cancel count = %d, want 1", test.session.canceled)
			}
			if !test.encoded {
				if err == nil || raw != nil {
					t.Fatalf("encodePreparationOrCancel = %x, %v; want an unusable-report failure", raw, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			completion := decodePreparation(t, raw).GetCompletion()
			if completion == nil ||
				completion.Report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED {
				t.Fatalf("unexpected completion: %v", completion)
			}
		})
	}
}

func TestEncodePreparationCancelsWhenTheChallengeCannotBeEncoded(t *testing.T) {
	session := pendingFakeSession()
	session.activationChallenge.Credential = make([]byte, attestation.MaxActivationMessageSize+1)
	if raw, err := encodePreparationOrCancel(session); raw != nil || err == nil {
		t.Fatalf("encodePreparationOrCancel = %x, %v; want an encoding failure", raw, err)
	}
	if session.canceled != 1 {
		t.Fatalf("cancel count = %d, want 1", session.canceled)
	}
}

func TestCompletionEncodesTheSessionReport(t *testing.T) {
	response, err := proto.Marshal(&attestuxv1.CredentialActivationResponse{
		Secret: bytes.Repeat([]byte{0xa5}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		complete func(*Verifier) ([]byte, error)
		calls    int
	}{
		{"complete", func(v *Verifier) ([]byte, error) { return v.CompleteActivation(response) }, 1},
		{"reject", (*Verifier).RejectActivation, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := NewVerifier()
			defer verifier.Close()
			session := &fakeVerificationSession{completeReport: attestationtest.FailedReport()}
			verifier.session = session
			raw, err := test.complete(verifier)
			if err != nil {
				t.Fatal(err)
			}
			if len(session.activationResponses) != test.calls {
				t.Fatalf("activation calls = %d, want %d", len(session.activationResponses), test.calls)
			}
			if test.calls != 0 && !bytes.Equal(session.activationResponses[0], response) {
				t.Fatalf("activation response = %x, want %x", session.activationResponses[0], response)
			}
			var completion attestuxv1.VerificationCompletion
			if err := proto.Unmarshal(raw, &completion); err != nil {
				t.Fatal(err)
			}
			if completion.Report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
				completion.Receipt.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED {
				t.Fatalf("unexpected completion: %v", &completion)
			}
		})
	}
}

func TestCompletionRequiresAUsableSession(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	if _, err := verifier.CompleteActivation([]byte{1}); err == nil {
		t.Fatal("completed without a session")
	}
	verifier.session = &fakeVerificationSession{completeErr: errors.New("secret mismatch")}
	if _, err := verifier.RejectActivation(); err == nil {
		t.Fatal("session error was ignored")
	}
	verifier.session = &fakeVerificationSession{completeReport: &attestuxv1.VerificationReport{}}
	if raw, err := verifier.RejectActivation(); err == nil || raw != nil {
		t.Fatalf("completion = %x, %v; want a nonterminal report refused", raw, err)
	}
}

func TestCloseCancelsTheSessionAndRejectsCalls(t *testing.T) {
	verifier := challengedVerifier(t, NewVerifier())
	session := pendingFakeSession()
	verifier.session = session
	verifier.Close()
	verifier.Close()
	if session.canceled != 1 {
		t.Fatalf("closed session cancel count = %d, want 1", session.canceled)
	}
	if _, err := verifier.IssueChallenge(); err == nil {
		t.Fatal("closed verifier issued a challenge")
	}
	if _, err := verifier.PrepareVerification([]byte{0xff}); err == nil {
		t.Fatal("closed verifier prepared evidence")
	}
	if _, err := verifier.CompleteActivation([]byte{1}); err == nil {
		t.Fatal("closed verifier completed an activation")
	}
}

func TestVerifierSerializesConcurrentCalls(t *testing.T) {
	verifier := &Verifier{session: &fakeVerificationSession{completeReport: attestationtest.FailedReport()}}
	var (
		start = make(chan struct{})
		group sync.WaitGroup
	)
	for caller := range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			switch caller % 4 {
			case 0:
				verifier.CompleteActivation([]byte{1})
			case 1:
				verifier.RejectActivation()
			case 2:
				verifier.Close()
			default:
				verifier.PrepareVerification(nil)
			}
		}()
	}
	close(start)
	group.Wait()
	if _, err := verifier.RejectActivation(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed verifier still completes: %v", err)
	}
}

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
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

type fakeVerificationSession struct {
	canceled            int
	report              *resultv1.VerificationReport
	activationChallenge *attestuxv1.CredentialActivationChallenge
	completeReport      *resultv1.VerificationReport
	completeErr         error
	evidenceInputs      [][]byte
}

func (s *fakeVerificationSession) Report() *resultv1.VerificationReport {
	if s.report == nil {
		return &resultv1.VerificationReport{}
	}
	return s.report
}

func (s *fakeVerificationSession) ActivationChallenge() *attestuxv1.CredentialActivationChallenge {
	return s.activationChallenge
}

func (s *fakeVerificationSession) CompleteEvidence(evidence []byte) (*resultv1.VerificationReport, error) {
	s.evidenceInputs = append(s.evidenceInputs, bytes.Clone(evidence))
	return s.completeReport, s.completeErr
}

func (s *fakeVerificationSession) RejectActivation() (*resultv1.VerificationReport, error) {
	return s.completeReport, s.completeErr
}

func (s *fakeVerificationSession) RejectEvidence() (*resultv1.VerificationReport, error) {
	return s.completeReport, s.completeErr
}

func (s *fakeVerificationSession) Cancel() {
	s.canceled++
}

func pendingFakeSession() *fakeVerificationSession {
	return &fakeVerificationSession{
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

func decodePreparation(t *testing.T, raw []byte) *resultv1.VerificationPreparation {
	t.Helper()
	var preparation resultv1.VerificationPreparation
	if err := proto.Unmarshal(raw, &preparation); err != nil {
		t.Fatal(err)
	}
	return &preparation
}

func TestIssueChallengeStartsKeyDiscoveryOnce(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	raw, err := verifier.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	var request attestuxv1.AttestationChallenge
	if err := proto.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request.ProtocolVersion != attestation.ProtocolVersion || len(request.ProtoReflect().GetUnknown()) != 0 {
		t.Fatalf("invalid key discovery: %v", &request)
	}
	if _, err := verifier.IssueChallenge(); err == nil {
		t.Fatal("issued a second request")
	}
}

func TestPrepareVerificationRequiresAnIssuedChallenge(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	if _, err := verifier.PrepareVerification([]byte{0xff}); err == nil {
		t.Fatal("verifier prepared a hello without issuing a challenge")
	}
}

func TestMalformedHelloProducesRetainableRejectedReport(t *testing.T) {
	verifier := challengedVerifier(t, NewVerifier())
	defer verifier.Close()
	hello := []byte{0xff}
	raw, err := verifier.PrepareVerification(hello)
	if err != nil {
		t.Fatal(err)
	}
	preparation := decodePreparation(t, raw)
	completion := preparation.GetCompletion()
	if completion == nil || preparation.GetActivationChallenge() != nil {
		t.Fatalf("unexpected terminal preparation: %v", preparation)
	}
	sum := sha256.Sum256(hello)
	report := completion.Report
	receipt := completion.Receipt
	if report == nil ||
		report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!bytes.Equal(report.EvidenceSha256, sum[:]) ||
		len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "malformed attestation hello") {
		t.Fatalf("unexpected malformed-hello report: %v", report)
	}
	if receipt == nil ||
		receipt.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!slices.Equal(receipt.Errors, report.Errors) {
		t.Fatalf("unexpected malformed-hello receipt: %v", receipt)
	}
	if _, err := verifier.PrepareVerification(hello); err == nil {
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
	challenge := decodePreparation(t, raw).GetActivationChallenge()
	if !proto.Equal(challenge, session.activationChallenge) {
		t.Fatalf("unexpected preparation: %v", challenge)
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
	// Each field fits on its own; the combined encoding exceeds the message limit.
	session.activationChallenge.Credential = make([]byte, attestation.MaxControlMessageSize)
	session.activationChallenge.EncryptedSecret = session.activationChallenge.Credential
	if raw, err := encodePreparationOrCancel(session); raw != nil || err == nil || !strings.Contains(err.Error(), "activation challenge exceeds local limits") {
		t.Fatalf("encodePreparationOrCancel = %x, %v; want the activation challenge limit", raw, err)
	}
	if session.canceled != 1 {
		t.Fatalf("cancel count = %d, want 1", session.canceled)
	}
}

func TestCompletionEncodesTheSessionReport(t *testing.T) {
	evidence := []byte{1, 2, 3}
	for _, test := range []struct {
		name     string
		complete func(*Verifier) ([]byte, error)
		calls    int
	}{
		{"complete", func(v *Verifier) ([]byte, error) { return v.CompleteEvidence(evidence) }, 1},
		{"reject activation", (*Verifier).RejectActivation, 0},
		{"reject evidence", (*Verifier).RejectEvidence, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := NewVerifier()
			defer verifier.Close()
			session := &fakeVerificationSession{completeReport: attestationtest.FailedReport()}
			report := proto.Clone(session.completeReport).(*resultv1.VerificationReport)
			verifier.session = session
			raw, err := test.complete(verifier)
			if err != nil {
				t.Fatal(err)
			}
			if len(session.evidenceInputs) != test.calls {
				t.Fatalf("evidence completion calls = %d, want %d", len(session.evidenceInputs), test.calls)
			}
			if test.calls != 0 && !bytes.Equal(session.evidenceInputs[0], evidence) {
				t.Fatalf("evidence = %x, want %x", session.evidenceInputs[0], evidence)
			}
			var completion resultv1.VerificationCompletion
			if err := proto.Unmarshal(raw, &completion); err != nil {
				t.Fatal(err)
			}
			want := &resultv1.VerificationCompletion{
				Report: report,
				Receipt: &attestuxv1.VerificationReceipt{
					Errors:      report.Errors,
					TrustPolicy: report.TrustPolicy,
					Status:      report.Status,
				},
			}
			if !proto.Equal(&completion, want) {
				t.Fatalf("completion = %v, want %v", &completion, want)
			}
			if len(raw) > maxCompletionBytes {
				t.Fatalf("encoded completion size %d exceeds its budget", len(raw))
			}
		})
	}
}

func TestCompletionRequiresAUsableSession(t *testing.T) {
	verifier := NewVerifier()
	defer verifier.Close()
	if _, err := verifier.CompleteEvidence([]byte{1}); err == nil {
		t.Fatal("completed without a session")
	}
	verifier.session = &fakeVerificationSession{completeErr: errors.New("nonce mismatch")}
	if _, err := verifier.RejectActivation(); err == nil {
		t.Fatal("session error was ignored")
	}
	verifier.session = &fakeVerificationSession{completeReport: &resultv1.VerificationReport{}}
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
		t.Fatal("closed verifier prepared a hello")
	}
	if _, err := verifier.CompleteEvidence([]byte{1}); err == nil {
		t.Fatal("closed verifier completed evidence verification")
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
				verifier.CompleteEvidence([]byte{1})
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

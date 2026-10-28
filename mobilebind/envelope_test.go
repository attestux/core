package mobilebind

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

func TestMarshalPreparationRejectsAnOversizedActivationChallenge(t *testing.T) {
	raw, err := marshalPreparation(
		pendingFakeSession().report,
		&attestuxv1.CredentialActivationChallenge{
			EndorsementKeySha256: make([]byte, sha256.Size),
			Credential:           make([]byte, attestation.MaxActivationMessageSize),
			EncryptedSecret:      make([]byte, attestation.MaxActivationMessageSize),
		},
	)
	if raw != nil {
		t.Fatal("an oversized activation challenge was encoded")
	}
	if err == nil || !strings.Contains(err.Error(), "activation challenge exceeds local limits") {
		t.Fatalf("error = %v, want the activation challenge limit", err)
	}
}

func TestMarshalPreparationRejectsAnOversizedEncoding(t *testing.T) {
	report := pendingFakeSession().report
	report.Warnings = []string{strings.Repeat("w", maxPendingPreparationBytes+1)}
	raw, err := marshalPreparation(
		report,
		&attestuxv1.CredentialActivationChallenge{
			EndorsementKeySha256: make([]byte, sha256.Size),
			Credential:           []byte{1},
			EncryptedSecret:      []byte{1},
		},
	)
	if raw != nil {
		t.Fatal("an oversized preparation was encoded")
	}
	if err == nil || !strings.Contains(err.Error(), "exceeds local limits") {
		t.Fatalf("error = %v, want the encoded-size limit", err)
	}
}

func TestMarshalCompletionEncodesADecodableCompletion(t *testing.T) {
	report := attestationtest.FailedReport()
	raw, err := marshalCompletion(report)
	if err != nil {
		t.Fatal(err)
	}

	var completion attestuxv1.VerificationCompletion
	if err := proto.Unmarshal(raw, &completion); err != nil {
		t.Fatalf("encoded completion did not decode: %v", err)
	}
	if completion.Report.DeviceId != report.DeviceId ||
		completion.Receipt.DeviceId != report.DeviceId {
		t.Fatalf("completion lost the device identity: %v", &completion)
	}
	if completion.Receipt.Status != completion.Report.Status {
		t.Fatalf("encoded receipt disagrees with its report: %v", &completion)
	}
	if len(raw) > maxCompletionBytes {
		t.Fatalf("encoded completion size %d exceeds its budget", len(raw))
	}
}

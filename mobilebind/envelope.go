package mobilebind

import (
	"errors"
	"fmt"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/verifier"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

const (
	maxProtobufEnvelopeOverhead = 1024
	maxCompletionBytes          = verifier.MaxReportSize +
		verifier.MaxReceiptSize + maxProtobufEnvelopeOverhead
	maxPendingPreparationBytes = verifier.MaxReportSize +
		attestation.MaxActivationMessageSize + maxProtobufEnvelopeOverhead
)

func marshalCompletion(report *attestuxv1.VerificationReport) ([]byte, error) {
	completion, err := verifier.CompletionForReport(report)
	if err != nil {
		return nil, err
	}
	return marshalBounded(completion, maxCompletionBytes, "verification completion")
}

// The activation challenge still has to fit the wire limit inside this local envelope.
func marshalPreparation(
	report *attestuxv1.VerificationReport,
	challenge *attestuxv1.CredentialActivationChallenge,
) ([]byte, error) {
	preparation := &attestuxv1.VerificationPreparation{}
	limit := maxCompletionBytes
	if challenge == nil {
		completion, err := verifier.CompletionForReport(report)
		if err != nil {
			return nil, err
		}
		preparation.Result = &attestuxv1.VerificationPreparation_Completion{Completion: completion}
	} else {
		if proto.Size(challenge) > attestation.MaxActivationMessageSize {
			return nil, errors.New("activation challenge exceeds local limits")
		}
		preparation.Result = &attestuxv1.VerificationPreparation_Pending{
			Pending: &attestuxv1.PendingVerification{Report: report, ActivationChallenge: challenge},
		}
		limit = maxPendingPreparationBytes
	}
	return marshalBounded(preparation, limit, "verification preparation")
}

func marshalBounded(
	message proto.Message,
	limit int,
	name string,
) ([]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", name, err)
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%s exceeds local limits", name)
	}
	return raw, nil
}

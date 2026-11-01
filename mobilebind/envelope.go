package mobilebind

import (
	"errors"
	"fmt"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/verifier"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

const (
	maxProtobufEnvelopeOverhead = 1024
	maxCompletionBytes          = verifier.MaxReportSize +
		verifier.MaxReceiptSize + maxProtobufEnvelopeOverhead
)

func marshalCompletion(report *resultv1.VerificationReport) ([]byte, error) {
	completion, err := verifier.CompletionForReport(report)
	if err != nil {
		return nil, err
	}
	return marshalBounded(completion, "verification completion")
}

// The activation challenge still has to fit the wire limit inside this local envelope.
func marshalPreparation(
	report *resultv1.VerificationReport,
	challenge *attestuxv1.CredentialActivationChallenge,
) ([]byte, error) {
	preparation := &resultv1.VerificationPreparation{}
	if challenge == nil {
		completion, err := verifier.CompletionForReport(report)
		if err != nil {
			return nil, err
		}
		preparation.Result = &resultv1.VerificationPreparation_Completion{Completion: completion}
	} else {
		if proto.Size(challenge) > attestation.MaxControlMessageSize {
			return nil, errors.New("activation challenge exceeds local limits")
		}
		preparation.Result = &resultv1.VerificationPreparation_ActivationChallenge{
			ActivationChallenge: challenge,
		}
	}
	return marshalBounded(preparation, "verification preparation")
}

func marshalBounded(
	message proto.Message,
	name string,
) ([]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", name, err)
	}
	if len(raw) > maxCompletionBytes {
		return nil, fmt.Errorf("%s exceeds local limits", name)
	}
	return raw, nil
}

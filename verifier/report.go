package verifier

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

// The report is a terminal report produced by a session, passed on unmodified.
func CompletionForReport(
	report *attestuxv1.VerificationReport,
) (*attestuxv1.VerificationCompletion, error) {
	if report == nil {
		return nil, errors.New("verification completion is missing a report")
	}
	if proto.Size(report) > MaxReportSize {
		report = rejectOversizedReport(report)
	} else {
		report = proto.Clone(report).(*attestuxv1.VerificationReport)
	}
	if len(report.EvidenceSha256) != sha256.Size {
		return nil, errors.New("terminal verification report has an invalid evidence hash")
	}
	switch report.Status {
	case attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED:
		_, recognized := attestation.TrustPolicyName(report.TrustPolicy)
		if len(report.Errors) != 0 || report.DeviceId == "" || !recognized ||
			len(report.EndorsementKeySha256) != sha256.Size {
			return nil, errors.New("verified report is incomplete")
		}
	case attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED:
		if len(report.Errors) == 0 {
			return nil, errors.New("failed report has no error details")
		}
	default:
		return nil, errors.New("terminal verification report has a nonterminal status")
	}
	return &attestuxv1.VerificationCompletion{
		Report: report,
		Receipt: &attestuxv1.VerificationReceipt{
			DeviceId:       report.DeviceId,
			Errors:         slices.Clone(report.Errors),
			EvidenceSha256: bytes.Clone(report.EvidenceSha256),
			Status:         report.Status,
			TrustPolicy:    report.TrustPolicy,
		},
	}, nil
}

// Copy only these fields so a new report field can't sneak trust claims into fallback.
func rejectOversizedReport(report *attestuxv1.VerificationReport) *attestuxv1.VerificationReport {
	omitted := report.OmittedEventCount + uint32(len(report.Events))
	return &attestuxv1.VerificationReport{
		DeviceId:       report.DeviceId,
		EvidenceSha256: bytes.Clone(report.EvidenceSha256),
		Status:         attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED,
		Errors: append(
			slices.Clone(report.Errors),
			"normalized report exceeded local limits; raw evidence was retained",
		),
		EventLogIncomplete: omitted > 0,
		OmittedEventCount:  omitted,
	}
}

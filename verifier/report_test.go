package verifier

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/attestux/core/attestation/attestationtest"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

func TestCompletionForReportRejectsUnusableReports(t *testing.T) {
	nonterminal := attestationtest.FailedReport()
	nonterminal.Status =
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION

	shortHash := attestationtest.FailedReport()
	shortHash.EvidenceSha256 = make([]byte, sha256.Size-1)

	failedWithoutErrors := attestationtest.FailedReport()
	failedWithoutErrors.Errors = nil

	verifiedWithErrors := attestationtest.FailedReport()
	verifiedWithErrors.Status =
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
	verifiedWithErrors.EndorsementKeySha256 = make([]byte, sha256.Size)

	unknownPolicy := attestationtest.FailedReport()
	unknownPolicy.Status =
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
	unknownPolicy.Errors = nil
	unknownPolicy.EndorsementKeySha256 = make([]byte, sha256.Size)
	unknownPolicy.TrustPolicy = attestuxv1.TrustPolicy_TRUST_POLICY_UNSPECIFIED

	verifiedWithoutDevice := proto.Clone(unknownPolicy).(*attestuxv1.VerificationReport)
	verifiedWithoutDevice.TrustPolicy = attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON
	verifiedWithoutDevice.DeviceId = ""

	verifiedWithShortEKHash := proto.Clone(unknownPolicy).(*attestuxv1.VerificationReport)
	verifiedWithShortEKHash.TrustPolicy = attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON
	verifiedWithShortEKHash.EndorsementKeySha256 = make([]byte, sha256.Size-1)

	for name, test := range map[string]struct {
		report *attestuxv1.VerificationReport
		want   string
	}{
		"no report":                   {nil, "missing a report"},
		"nonterminal status":          {nonterminal, "nonterminal status"},
		"short evidence hash":         {shortHash, "invalid evidence hash"},
		"failed without errors":       {failedWithoutErrors, "no error details"},
		"verified with errors":        {verifiedWithErrors, "verified report is incomplete"},
		"unrecognized policy":         {unknownPolicy, "verified report is incomplete"},
		"verified without device":     {verifiedWithoutDevice, "verified report is incomplete"},
		"verified with short EK hash": {verifiedWithShortEKHash, "verified report is incomplete"},
	} {
		t.Run(name, func(t *testing.T) {
			completion, err := CompletionForReport(test.report)
			if completion != nil {
				t.Fatal("an unusable report produced a completion")
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestCompletionForReportProducesACompactReceipt(t *testing.T) {
	report := &attestuxv1.VerificationReport{
		DeviceId:             "device",
		Status:               attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED,
		EvidenceSha256:       make([]byte, sha256.Size),
		EndorsementKeySha256: make([]byte, sha256.Size),
		Pcrs:                 make([]*attestuxv1.PcrResult, 48),
		Events:               make([]*attestuxv1.Event, 1234),
		TrustPolicy:          attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
	}
	completion, err := CompletionForReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if completion.Report == report {
		t.Fatal("completion retained the caller's mutable report")
	}

	receipt := completion.Receipt
	if receipt == nil ||
		receipt.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED ||
		receipt.DeviceId != "device" ||
		receipt.TrustPolicy !=
			attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON {
		t.Fatalf("unexpected receipt: %v", receipt)
	}
	if proto.Size(receipt) >= proto.Size(completion.Report) {
		t.Fatalf(
			"receipt size %d is not smaller than report size %d",
			proto.Size(receipt),
			proto.Size(completion.Report),
		)
	}
}

func TestCompletionForReportRejectsOversizedReports(t *testing.T) {
	report := &attestuxv1.VerificationReport{
		DeviceId:             "device",
		Status:               attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED,
		Errors:               []string{"quote signature did not verify"},
		EvidenceSha256:       make([]byte, sha256.Size),
		EndorsementKeySha256: make([]byte, sha256.Size),
		TrustPolicy:          attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		Limitations:          []string{"certificate revocation is not checked"},
		Warnings:             []string{strings.Repeat("w", MaxReportSize)},
		Events:               []*attestuxv1.Event{{}, {}},
		OmittedEventCount:    3,
	}
	completion, err := CompletionForReport(report)
	if err != nil {
		t.Fatal(err)
	}
	rejected := completion.Report
	if size := proto.Size(rejected); size > MaxReportSize {
		t.Fatalf("rejected report size = %d, want at most %d", size, MaxReportSize)
	}
	if rejected.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		rejected.DeviceId != "device" ||
		len(rejected.Warnings)+len(rejected.Events)+len(rejected.Limitations) != 0 ||
		!rejected.EventLogIncomplete || rejected.OmittedEventCount != 5 ||
		len(rejected.Errors) != 2 ||
		rejected.Errors[0] != report.Errors[0] ||
		!strings.Contains(rejected.Errors[1], "exceeded local limits") ||
		!bytes.Equal(rejected.EvidenceSha256, report.EvidenceSha256) ||
		describesTrust(rejected) {
		t.Fatalf("unexpected rejected report: %v", rejected)
	}
	if completion.Receipt.Status != rejected.Status ||
		completion.Receipt.DeviceId != rejected.DeviceId ||
		completion.Receipt.TrustPolicy != attestuxv1.TrustPolicy_TRUST_POLICY_UNSPECIFIED ||
		!bytes.Equal(completion.Receipt.EvidenceSha256, report.EvidenceSha256) {
		t.Fatalf("unexpected rejected receipt: %v", completion.Receipt)
	}
}

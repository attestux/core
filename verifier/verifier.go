package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"google.golang.org/protobuf/proto"
)

type VerificationSession struct {
	mu                   sync.Mutex
	report               *attestuxv1.VerificationReport
	activationChallenge  *attestuxv1.CredentialActivationChallenge
	expectedSecret       []byte
	policy               verificationPolicy
	endorsementKeySHA256 []byte
}

func PrepareVerification(
	evidenceBytes,
	expectedNonce []byte,
) (*VerificationSession, error) {
	return prepareVerificationWithPolicies(
		evidenceBytes,
		expectedNonce,
		runtimeVerificationPolicies(),
		time.Now(),
	)
}

type verificationPolicy struct {
	id         attestuxv1.TrustPolicy
	limitation string
	trust      certificateTrust
}

func selectEndorsementPolicy(
	keys []*attestuxv1.EndorsementKey,
	policies []verificationPolicy,
	now time.Time,
) (*validatedEndorsement, verificationPolicy, error) {
	if len(policies) == 0 {
		return nil, verificationPolicy{}, errors.New(
			"no endorsement certificate trust policy is configured",
		)
	}
	var failures []error
	for _, policy := range policies {
		name, recognized := attestation.TrustPolicyName(policy.id)
		// Don't pass nil roots: that would trust the host CA store to endorse a TPM.
		if !recognized || policy.trust.roots == nil {
			failures = append(
				failures,
				fmt.Errorf("%s: invalid endorsement trust policy", name),
			)
			continue
		}
		endorsement, err := validateEndorsementsWithTrust(keys, policy.trust, now)
		if err == nil {
			return endorsement, policy, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", name, err))
	}
	return nil, verificationPolicy{}, errors.Join(failures...)
}

func prepareVerificationWithPolicies(
	evidenceBytes,
	expectedNonce []byte,
	policies []verificationPolicy,
	now time.Time,
) (*VerificationSession, error) {
	if err := attestation.ValidateChallengeNonce(expectedNonce); err != nil {
		return nil, fmt.Errorf("expected nonce: %w", err)
	}
	// Put bad evidence in the report. A bad nonce is the caller's error.
	report := &attestuxv1.VerificationReport{}
	var evidence attestuxv1.AttestationEvidence
	var pcrs []attest.PCR
	if len(evidenceBytes) == 0 || len(evidenceBytes) > attestation.MaxEvidenceSize {
		failReport(report, "malformed evidence: size %d is outside permitted range", len(evidenceBytes))
	} else if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(
		evidenceBytes,
		&evidence,
	); err != nil {
		failReport(report, "malformed evidence: %v", err)
	} else if err := attestation.ValidateEvidence(&evidence); err != nil {
		failReport(report, "%v", err)
	} else {
		report, pcrs = buildQuoteReportAndPCRs(&evidence, expectedNonce)
	}
	sum := sha256.Sum256(evidenceBytes)
	report.EvidenceSha256 = sum[:]
	session := &VerificationSession{report: report}
	if len(report.Errors) != 0 {
		return session, nil
	}
	if err := attestation.RequireSHA256SignatureEncoding(evidence.AkCreateSignature); err != nil {
		failReport(report, "attestation key creation signature: %v", err)
		return session, nil
	}

	endorsement, policy, err := selectEndorsementPolicy(
		evidence.EndorsementKeys,
		policies,
		now,
	)
	if err != nil {
		failReport(
			report,
			"endorsement certificate verification failed: %v",
			err,
		)
		return session, nil
	}
	// Don't name the policy or EK until activation ties them to the AK.
	session.policy = policy
	session.endorsementKeySHA256 = bytes.Clone(endorsement.publicSHA256)
	activation := attest.ActivationParameters{
		EK: endorsement.publicKey,
		AK: attest.AttestationParameters{
			Public:            bytes.Clone(evidence.AttestationPublic),
			CreateData:        bytes.Clone(evidence.AkCreateData),
			CreateAttestation: bytes.Clone(evidence.AkCreateAttestation),
			CreateSignature:   bytes.Clone(evidence.AkCreateSignature),
		},
	}
	// Check AK creation on its own so we can tell AK and EK failures apart.
	if err := activation.CheckAKParameters(); err != nil {
		failReport(
			report,
			"attestation key is not TPM-created: %v",
			err,
		)
		return session, nil
	}
	secret, encrypted, err := activation.Generate()
	if err != nil {
		failReport(
			report,
			"build credential activation challenge for the certified endorsement key: %v",
			err,
		)
		return session, nil
	}
	attachEventLogReplay(report, evidence.EventLog, pcrs)
	session.expectedSecret = secret
	session.activationChallenge = &attestuxv1.CredentialActivationChallenge{
		EndorsementKeySha256: bytes.Clone(endorsement.publicSHA256),
		Credential:           bytes.Clone(encrypted.Credential),
		EncryptedSecret:      bytes.Clone(encrypted.Secret),
	}
	return session, nil
}

func (s *VerificationSession) Report() *attestuxv1.VerificationReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.Clone(s.report).(*attestuxv1.VerificationReport)
}

func (s *VerificationSession) ActivationChallenge() *attestuxv1.CredentialActivationChallenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activationChallenge == nil {
		return nil
	}
	return proto.Clone(s.activationChallenge).(*attestuxv1.CredentialActivationChallenge)
}

func (s *VerificationSession) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearPendingActivation()
}

func (s *VerificationSession) RejectActivation() (
	*attestuxv1.VerificationReport,
	error,
) {
	return s.finishActivation(nil, "prover reported credential activation failure")
}

func (s *VerificationSession) CompleteActivationBytes(
	responseBytes []byte,
) (*attestuxv1.VerificationReport, error) {
	if len(responseBytes) == 0 ||
		len(responseBytes) > attestation.MaxActivationMessageSize {
		return s.finishActivation(nil, fmt.Sprintf("response has invalid size %d", len(responseBytes)))
	}
	var response attestuxv1.CredentialActivationResponse
	if err := proto.Unmarshal(responseBytes, &response); err != nil {
		return s.finishActivation(nil, fmt.Sprintf("response could not be decoded: %v", err))
	}
	return s.finishActivation(response.Secret, "")
}

// All activation outcomes consume the challenge and erase its secret under one lock.
func (s *VerificationSession) finishActivation(
	secret []byte,
	failure string,
) (*attestuxv1.VerificationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activationChallenge == nil {
		return nil, errors.New("verification session has no pending activation")
	}
	if failure == "" && subtle.ConstantTimeCompare(secret, s.expectedSecret) != 1 {
		failure = "TPM credential activation secret did not match"
	}

	s.clearPendingActivation()
	if failure != "" {
		failReport(s.report, "TPM credential activation failed: %s", failure)
	} else {
		s.report.Status = attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
		s.report.TrustPolicy = s.policy.id
		s.report.EndorsementKeySha256 = s.endorsementKeySHA256
		if s.policy.limitation != "" {
			s.report.Limitations = slices.Insert(s.report.Limitations, 0, s.policy.limitation)
		}
	}
	return proto.Clone(s.report).(*attestuxv1.VerificationReport), nil
}

func (s *VerificationSession) clearPendingActivation() {
	clear(s.expectedSecret)
	s.expectedSecret = nil
	s.activationChallenge = nil
}

// Every failure path appends one error and returns, so a report holds only a few.
func failReport(
	report *attestuxv1.VerificationReport,
	format string,
	args ...any,
) {
	report.Status =
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED
	report.Errors = append(report.Errors, diagnostic(format, args...))
}

func diagnostic(format string, args ...any) string {
	return truncateText(fmt.Sprintf(format, args...), maxDiagnosticMessageBytes)
}

func buildQuoteReportAndPCRs(
	e *attestuxv1.AttestationEvidence,
	expectedNonce []byte,
) (*attestuxv1.VerificationReport, []attest.PCR) {
	report := &attestuxv1.VerificationReport{
		Status: attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION,
	}
	deviceID, pcrs, pcrResults, err := verifyQuotedPCRs(e, expectedNonce)
	// Keep the verified quote identity even when a later check rejects the evidence.
	report.DeviceId = deviceID
	if err != nil {
		failReport(report, "%v", err)
		return report, nil
	}
	report.Pcrs = pcrResults

	// Don't describe the PCRs until the quote verifies.
	if warning := unsupportedPCRBankWarning(e); warning != "" {
		report.Warnings = append(report.Warnings, warning)
	}
	return report, pcrs
}

// Replay is expensive. Wait until AK and certified EK checks pass.
func attachEventLogReplay(
	report *attestuxv1.VerificationReport,
	eventLog []byte,
	pcrs []attest.PCR,
) {
	replay := replayEventLog(eventLog, pcrs, report.Pcrs, maxNormalizedEventBytes)
	report.Events = replay.events
	report.EventLogIncomplete = replay.incomplete
	report.OmittedEventCount = replay.omittedEventCount
	report.Warnings = append(report.Warnings, replay.warnings...)
	report.Limitations = append(
		report.Limitations,
		"Event type and decoded payload are descriptive metadata; quote and replay verification authenticate PCR values and event digests, not every semantic claim in event data.",
	)
}

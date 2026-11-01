package verifier

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/attestux/core/attestation"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"google.golang.org/protobuf/proto"
)

type VerificationSession struct {
	mu                   sync.Mutex
	report               *resultv1.VerificationReport
	activationChallenge  *attestuxv1.CredentialActivationChallenge
	expectedQuoteNonce   []byte
	keys                 *attestuxv1.AttestationKeys
	deviceID             string
	policy               verificationPolicy
	endorsementKeySHA256 []byte
}

func PrepareVerification(helloBytes []byte) *VerificationSession {
	return prepareVerificationWithPolicies(
		helloBytes,
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
	helloBytes []byte,
	policies []verificationPolicy,
	now time.Time,
) *VerificationSession {
	report := &resultv1.VerificationReport{
		Status: attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION,
	}
	sum := sha256.Sum256(helloBytes)
	report.EvidenceSha256 = sum[:]
	session := &VerificationSession{report: report}
	var hello attestuxv1.AttestationHello
	// Hello and evidence data may carry unknown metadata. Only challenges are
	// validated strictly by the prover, because they request actions; a response
	// cannot require an older prover to do anything new.
	if len(helloBytes) == 0 || len(helloBytes) > attestation.MaxControlMessageSize {
		failReport(report, "malformed attestation hello: size %d is outside permitted range", len(helloBytes))
	} else if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(helloBytes, &hello); err != nil {
		failReport(report, "malformed attestation hello: %v", err)
	} else if err := attestation.ValidateKeys(hello.Keys); err != nil {
		failReport(report, "%v", err)
	}
	if len(report.Errors) != 0 {
		return session
	}
	keys := hello.Keys
	// Validate the exact public encoding before creating an activation challenge.
	deviceID, err := attestation.DeviceID(keys.AttestationPublic)
	if err != nil {
		failReport(report, "parse attestation public key: %v", err)
		return session
	}
	if err := attestation.RequireSHA256SignatureEncoding(keys.AkCreateSignature); err != nil {
		failReport(report, "attestation key creation signature: %v", err)
		return session
	}

	endorsement, policy, err := selectEndorsementPolicy(
		keys.EndorsementKeys,
		policies,
		now,
	)
	if err != nil {
		failReport(
			report,
			"endorsement certificate verification failed: %v",
			err,
		)
		return session
	}
	// Don't name the policy or EK until activation ties them to the AK.
	session.policy = policy
	session.endorsementKeySHA256 = bytes.Clone(endorsement.publicSHA256)
	activation := attest.ActivationParameters{
		EK: endorsement.publicKey,
		AK: attest.AttestationParameters{
			Public:            bytes.Clone(keys.AttestationPublic),
			CreateData:        bytes.Clone(keys.AkCreateData),
			CreateAttestation: bytes.Clone(keys.AkCreateAttestation),
			CreateSignature:   bytes.Clone(keys.AkCreateSignature),
		},
	}
	// Check AK creation on its own so we can tell AK and EK failures apart.
	if err := activation.CheckAKParameters(); err != nil {
		failReport(
			report,
			"attestation key is not TPM-created: %v",
			err,
		)
		return session
	}
	secret, encrypted, err := activation.Generate()
	if err != nil {
		failReport(
			report,
			"build credential activation challenge for the certified endorsement key: %v",
			err,
		)
		return session
	}
	session.expectedQuoteNonce = attestation.ActivationQuoteNonce(secret)
	clear(secret)
	session.keys = keys
	session.deviceID = deviceID
	session.activationChallenge = &attestuxv1.CredentialActivationChallenge{
		EndorsementKeySha256: bytes.Clone(endorsement.publicSHA256),
		Credential:           bytes.Clone(encrypted.Credential),
		EncryptedSecret:      bytes.Clone(encrypted.Secret),
	}
	return session
}

func (s *VerificationSession) Report() *resultv1.VerificationReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proto.Clone(s.report).(*resultv1.VerificationReport)
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

func (s *VerificationSession) RejectActivation() (*resultv1.VerificationReport, error) {
	return s.completeEvidence(nil, "TPM credential activation failed: prover reported credential activation failure")
}

func (s *VerificationSession) RejectEvidence() (*resultv1.VerificationReport, error) {
	return s.completeEvidence(nil, "prover reported attestation failure")
}

func (s *VerificationSession) CompleteEvidence(evidenceBytes []byte) (*resultv1.VerificationReport, error) {
	return s.completeEvidence(evidenceBytes, "")
}

func (s *VerificationSession) completeEvidence(evidenceBytes []byte, failure string) (*resultv1.VerificationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activationChallenge == nil {
		return nil, errors.New("verification session has no pending activation")
	}
	defer s.clearPendingActivation()
	report := s.report
	if failure != "" {
		failReport(report, "%s", failure)
		return proto.Clone(report).(*resultv1.VerificationReport), nil
	}
	sum := sha256.Sum256(evidenceBytes)
	report.EvidenceSha256 = sum[:]
	var evidence attestuxv1.AttestationEvidence
	if len(evidenceBytes) == 0 || len(evidenceBytes) > attestation.MaxEvidenceSize {
		failReport(report, "malformed evidence: size %d is outside permitted range", len(evidenceBytes))
	} else if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(evidenceBytes, &evidence); err != nil {
		failReport(report, "malformed evidence: %v", err)
	} else if err := attestation.ValidateEvidence(&evidence); err != nil {
		failReport(report, "%v", err)
	} else if !proto.Equal(evidence.Keys, s.keys) {
		failReport(report, "evidence keys do not match the credential activation challenge")
	} else {
		pcrs, pcrResults, err := verifyQuotedPCRs(&evidence, s.expectedQuoteNonce)
		if err != nil {
			failReport(report, "%v", err)
		} else {
			report.DeviceId = s.deviceID
			report.Pcrs = pcrResults
			if warning := unsupportedPCRBankWarning(&evidence); warning != "" {
				report.Warnings = append(report.Warnings, warning)
			}
			attachEventLogReplay(report, evidence.EventLog, pcrs)
			report.Status = attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
			report.TrustPolicy = s.policy.id
			report.EndorsementKeySha256 = bytes.Clone(s.endorsementKeySHA256)
			if s.policy.limitation != "" {
				report.Limitations = slices.Insert(report.Limitations, 0, s.policy.limitation)
			}
		}
	}
	return proto.Clone(report).(*resultv1.VerificationReport), nil
}

func (s *VerificationSession) clearPendingActivation() {
	clear(s.expectedQuoteNonce)
	s.expectedQuoteNonce = nil
	s.activationChallenge = nil
	s.keys = nil
	s.deviceID = ""
}

// Every failure path appends one error and returns, so a report holds only a few.
func failReport(
	report *resultv1.VerificationReport,
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

// Replay is expensive. Run it only after the challenged key's quote verifies.
func attachEventLogReplay(
	report *resultv1.VerificationReport,
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

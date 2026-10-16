package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/core/verifier/testtrust"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

func TestUnsupportedPCRBankWarningNamesTheBank(t *testing.T) {
	e := attestationtest.MinimallyShapedEvidence()
	e.PcrBanks = append(e.PcrBanks, attestationtest.MakeUnsupportedPCRBank(e, 0x000d, 64))
	warning := unsupportedPCRBankWarning(e)
	if !strings.Contains(warning, "SHA-512") ||
		!strings.Contains(warning, "only SHA-256 was verified") {
		t.Fatalf("unexpected unsupported-bank warning: %q", warning)
	}
}

func TestRejectActivationClearsSessionSecrets(t *testing.T) {
	session := newActivationTestSession(t)
	secret := session.expectedSecret
	report, err := session.RejectActivation()
	if err != nil {
		t.Fatal(err)
	}
	if report.Status !=
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!containsMessage(report.Errors, "prover reported") {
		t.Fatalf("unexpected rejected report: %v", report)
	}
	requireActivationFinished(t, session, secret)
}

func TestPrepareVerificationReportsInvalidEvidence(t *testing.T) {
	e := attestationtest.MinimallyShapedEvidence()
	e.EndorsementKeys = nil
	session, err := PrepareVerification(marshalEvidence(t, e), bytes.Repeat([]byte{2}, 20))
	if err != nil {
		t.Fatal(err)
	}
	report := session.Report()
	if report.Status !=
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!containsMessage(report.Errors, "invalid endorsement-key count") {
		t.Fatalf("invalid evidence was accepted: %v", report)
	}
}

func TestPrepareVerificationRejectsEvidenceOutsideSizeRange(t *testing.T) {
	for _, size := range []int{0, attestation.MaxEvidenceSize + 1} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			session, err := PrepareVerification(make([]byte, size), make([]byte, 20))
			if err != nil {
				t.Fatal(err)
			}
			report := session.Report()
			if session.ActivationChallenge() != nil || len(report.Errors) != 1 ||
				!strings.Contains(report.Errors[0], fmt.Sprintf("size %d is outside permitted range", size)) {
				t.Fatalf("evidence of %d bytes was not rejected by size: %v", size, report)
			}
		})
	}
}

func TestFailReportBoundsTheDiagnostic(t *testing.T) {
	report := &attestuxv1.VerificationReport{}
	failReport(report, "%s", strings.Repeat("e", maxDiagnosticMessageBytes+1))
	if got := len(report.Errors[0]); got != maxDiagnosticMessageBytes+len("...") {
		t.Fatalf("diagnostic length = %d, want the %d byte cap plus an ellipsis", got, maxDiagnosticMessageBytes)
	}
}

func TestPrepareVerificationRejectsInvalidExpectedNonce(t *testing.T) {
	for _, size := range []int{0, 15, attestation.MaxNonceSize + 1} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			if _, err := PrepareVerification(
				[]byte{1},
				make([]byte, size),
			); err == nil || !strings.Contains(err.Error(), "expected nonce") {
				t.Fatalf("invalid expected nonce returned %v", err)
			}
		})
	}
}

func TestCompleteActivationBytesAcceptsOnlyAValidResponse(t *testing.T) {
	for _, test := range []struct {
		name      string
		response  func(t testing.TB, expected []byte) []byte
		wantError string
	}{
		{
			name: "correct secret",
			response: func(t testing.TB, expected []byte) []byte {
				response, err := proto.Marshal(&attestuxv1.CredentialActivationResponse{
					Secret: bytes.Clone(expected),
				})
				if err != nil {
					t.Fatal(err)
				}
				return response
			},
		},
		{
			name:      "empty",
			response:  func(testing.TB, []byte) []byte { return nil },
			wantError: "invalid size 0",
		},
		{
			name: "oversized",
			response: func(testing.TB, []byte) []byte {
				return make([]byte, attestation.MaxActivationMessageSize+1)
			},
			wantError: fmt.Sprintf("invalid size %d", attestation.MaxActivationMessageSize+1),
		},
		{
			name:      "malformed protobuf",
			response:  func(testing.TB, []byte) []byte { return []byte{0xff} },
			wantError: "could not be decoded",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := newActivationTestSession(t)
			secret := session.expectedSecret
			response := test.response(t, secret)
			report, err := session.CompleteActivationBytes(response)
			if err != nil {
				t.Fatal(err)
			}
			want := attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED
			if test.wantError == "" {
				want = attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
			}
			if report.Status != want {
				t.Fatalf("status = %v, want %v: %v", report.Status, want, report)
			}
			if test.wantError != "" && !containsMessage(report.Errors, test.wantError) {
				t.Fatalf("errors = %q, want %q", report.Errors, test.wantError)
			}
			requireActivationFinished(t, session, secret)
			snapshot := session.Report()
			report.Status = attestuxv1.VerificationStatus_VERIFICATION_STATUS_UNSPECIFIED
			report.EvidenceSha256[0] ^= 0xff
			if len(report.Errors) > 0 {
				report.Errors[0] = "changed by caller"
			}
			if len(report.EndorsementKeySha256) > 0 {
				report.EndorsementKeySha256[0] ^= 0xff
			}
			if !proto.Equal(session.Report(), snapshot) {
				t.Fatal("changing the returned report changed the session")
			}
		})
	}
}

func softwareEvidence(t testing.TB) ([]byte, []byte, *endorsementCertificateFixture) {
	t.Helper()
	fixture := newEndorsementCertificateFixture(t)
	evidence, nonce := softwareEvidenceWithFixture(t, fixture, nil)
	return marshalEvidence(t, evidence), nonce, fixture
}

// Extend PCR 7 so the quote covers the mutated log. A nil ak gets a fresh key.
func softwareEvidenceWithFixture(
	t testing.TB,
	fixture *endorsementCertificateFixture,
	ak *softwareAK,
	events ...logEvent,
) (*attestuxv1.AttestationEvidence, []byte) {
	t.Helper()
	if ak == nil {
		ak = newSoftwareAK(t)
	}
	nonce := bytes.Repeat([]byte{0x22}, 20)
	selection := allAttestedPCRs()
	pcr7 := extendedSHA256PCR(events...)
	composite := sha256.New()
	for index := range selection.PCRs {
		if index == 7 {
			composite.Write(pcr7)
		} else {
			composite.Write(make([]byte, sha256.Size))
		}
	}
	evidence := ak.quoteEvidence(t, nonce, selection, composite.Sum(nil))
	evidence.PcrBanks[0].Pcrs[7].Digest = pcr7
	evidence.EndorsementKeys = []*attestuxv1.EndorsementKey{fixture.issue(t, 2, nil)}
	evidence.EventLog = cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, events...)
	return evidence, nonce
}

func (fixture *endorsementCertificateFixture) policy() verificationPolicy {
	return verificationPolicy{
		id:         attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		limitation: "test policy limitation",
		trust:      certificateTrust{roots: fixture.roots},
	}
}

func newActivationTestSession(t *testing.T) *VerificationSession {
	t.Helper()
	raw, nonce, fixture := softwareEvidence(t)
	session, err := prepareVerificationWithPolicies(
		raw,
		nonce,
		[]verificationPolicy{fixture.policy()},
		fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if session.ActivationChallenge() == nil {
		t.Fatalf("software evidence was not challenged: %v", session.Report().Errors)
	}
	return session
}

func TestKeepAttestedPCREventsKeepsOnlyAttestedRegisters(t *testing.T) {
	events := []attest.Event{
		{Index: -1},
		{Index: 0},
		{Index: attestation.AttestedPCRCount - 1},
		{Index: attestation.AttestedPCRCount},
		{Index: 23},
		{Index: attestation.MaxPCRCount},
	}
	got, invalid := keepAttestedPCREvents(events)
	if len(got) != 2 || got[0].Index != 0 ||
		got[1].Index != attestation.AttestedPCRCount-1 {
		t.Fatalf("keepAttestedPCREvents = %v", got)
	}
	if invalid != 2 {
		t.Fatalf("invalid event count = %d, want 2", invalid)
	}
}

func TestSetPCRReplayedFillsOnlyTheMatchingIndex(t *testing.T) {
	results := []*attestuxv1.PcrResult{
		{HashAlgorithm: attestation.TPMAlgSHA256, Pcr: &attestuxv1.Pcr{Index: 5}},
		{HashAlgorithm: attestation.TPMAlgSHA256, Pcr: &attestuxv1.Pcr{Index: 7}},
	}
	setPCRReplayed(results, 7, 3, true)
	if results[0].EventLogReplayed || !results[1].EventLogReplayed {
		t.Fatalf("replay result = %#v", results)
	}
	if results[0].ReplayedEventCount != 0 ||
		results[1].ReplayedEventCount != 3 {
		t.Fatalf("replay count = %#v", results)
	}
	if results[0].ReplayUsedUnloggedEvents ||
		!results[1].ReplayUsedUnloggedEvents {
		t.Fatalf("replay workaround = %#v", results)
	}
}

// Keep the root fixed so corpus certificates work across workers and later runs.
func newFuzzEndorsementCertificateFixture(t testing.TB) *endorsementCertificateFixture {
	t.Helper()
	rootBlock, _ := pem.Decode(testtrust.RootPEM)
	keyBlock, _ := pem.Decode(testtrust.RootKeyPEM)
	if rootBlock == nil || keyBlock == nil {
		t.Fatal("missing fuzz root certificate or key")
		return nil
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("fuzz root key has type %T, want ECDSA", key)
	}
	return newEndorsementCertificateFixtureForRoot(t, root, rootKey, time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC))
}

func FuzzPrepareVerification(f *testing.F) {
	fixture := newFuzzEndorsementCertificateFixture(f)
	evidence, nonce := softwareEvidenceWithFixture(f, fixture, nil)
	raw := marshalEvidence(f, evidence)
	policies := []verificationPolicy{fixture.policy()}
	// The fixed root must keep the seeds accepted under a fresh fixture, or
	// the corpus silently degrades to rejected inputs.
	seed, err := prepareVerificationWithPolicies(raw, nonce, []verificationPolicy{newFuzzEndorsementCertificateFixture(f).policy()}, fixture.now)
	if err != nil || seed.ActivationChallenge() == nil {
		f.Fatalf("seed was rejected under a fresh fixture: %v", err)
	}
	seed.Cancel()
	f.Add(raw, nonce)
	measured, nonce := softwareEvidenceWithFixture(f, fixture, nil, logEvent{pcrIndex: 7, eventType: 5, data: []byte("seed measurement")})
	f.Add(marshalEvidence(f, measured), nonce)
	f.Add(marshalEvidence(f, attestationtest.MinimallyShapedEvidence()), bytes.Repeat([]byte{2}, 20))
	f.Add([]byte{0xff}, []byte{2})
	f.Fuzz(func(t *testing.T, evidence, nonce []byte) {
		if len(evidence) > 1<<20 {
			t.Skip()
		}
		session, err := prepareVerificationWithPolicies(evidence, nonce, policies, fixture.now)
		if (err != nil) != (attestation.ValidateChallengeNonce(nonce) != nil) {
			t.Fatalf("error %v does not follow the nonce validity", err)
		}
		if err != nil {
			return
		}
		report := session.Report()
		challenge := session.ActivationChallenge()
		if sum := sha256.Sum256(evidence); !bytes.Equal(report.EvidenceSha256, sum[:]) {
			t.Fatal("report does not hash the received evidence")
		}
		for _, text := range slices.Concat(report.Errors, report.Warnings, report.Limitations) {
			if len(text) > maxDiagnosticMessageBytes+len("...") || !utf8.ValidString(text) {
				t.Fatalf("unbounded or invalid diagnostic %q", text)
			}
		}
		if (challenge != nil) != (len(report.Errors) == 0) {
			t.Fatalf("challenge issued = %v with errors %q", challenge != nil, report.Errors)
		}
		if challenge == nil {
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED {
				t.Fatalf("rejected evidence has status %v", report.Status)
			}
			if _, err := CompletionForReport(report); err != nil {
				t.Fatalf("rejected report cannot complete: %v", err)
			}
			return
		}
		if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION ||
			report.DeviceId == "" || len(report.Pcrs) != attestation.AttestedPCRCount ||
			describesTrust(report) || len(challenge.EndorsementKeySha256) != sha256.Size {
			t.Fatalf("pending report %v; want an identified device, no trust facts and a full challenge", report)
		}
		if _, err := proto.Marshal(report); err != nil {
			t.Fatalf("pending report does not marshal: %v", err)
		}
		secret := session.expectedSecret
		session.Cancel()
		requireActivationFinished(t, session, secret)
	})
}

func TestSelectEndorsementPolicyRequiresConfiguredPolicy(t *testing.T) {
	_, _, err := selectEndorsementPolicy(nil, nil, time.Now())
	if err == nil ||
		!strings.Contains(err.Error(), "no endorsement certificate trust policy") {
		t.Fatalf("empty policy set returned %v", err)
	}
}

func TestSelectEndorsementPolicyRefusesPoliciesThatCannotAnchorTrust(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	keys := []*attestuxv1.EndorsementKey{fixture.issue(t, 2, nil)}

	for name, policies := range map[string][]verificationPolicy{
		"no roots": {{
			id:    attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
			trust: certificateTrust{},
		}},
		"unrecognized policy": {{
			id:    attestuxv1.TrustPolicy_TRUST_POLICY_UNSPECIFIED,
			trust: certificateTrust{roots: fixture.roots},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			endorsement, _, err := selectEndorsementPolicy(keys, policies, fixture.now)
			if endorsement != nil {
				t.Fatal("an unusable trust policy produced an endorsement")
			}
			if err == nil ||
				!strings.Contains(err.Error(), "invalid endorsement trust policy") {
				t.Fatalf("error = %v, want an invalid-policy rejection", err)
			}
		})
	}
}

func TestSelectEndorsementPolicyTriesEveryConfiguredPolicy(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	keys := []*attestuxv1.EndorsementKey{fixture.issue(t, 2, nil)}
	unrelated := verificationPolicy{
		id:    attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		trust: certificateTrust{roots: x509.NewCertPool()},
	}
	matching := verificationPolicy{
		id:    attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR,
		trust: certificateTrust{roots: fixture.roots},
	}

	endorsement, selected, err := selectEndorsementPolicy(
		keys,
		[]verificationPolicy{unrelated, matching},
		fixture.now,
	)
	if err != nil {
		t.Fatalf("later matching policy was not reached: %v", err)
	}
	if selected.id != matching.id {
		t.Fatalf("selected policy = %v, want the one that anchors the EK", selected.id)
	}
	publicSum := sha256.Sum256(fixture.publicDER)
	if !bytes.Equal(endorsement.publicSHA256, publicSum[:]) {
		t.Fatal("selection returned an endorsement for a different key")
	}

	_, _, err = selectEndorsementPolicy(
		keys,
		[]verificationPolicy{unrelated, {id: matching.id, trust: certificateTrust{}}},
		fixture.now,
	)
	if err == nil {
		t.Fatal("exhausted policies were accepted")
	}
	for _, want := range []string{"Nuvoton", "AttesTux simulator"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("joined failure %q omits %q", err, want)
		}
	}
}

func TestPrepareVerificationRejectionsKeepDeviceAttribution(t *testing.T) {
	for _, test := range []struct {
		name       string
		untrusted  bool
		attributes legacytpm2.KeyProp
		change     func(testing.TB, *softwareAK, *attestuxv1.AttestationEvidence)
		wantError  string
	}{
		{
			name:      "untrusted EK",
			untrusted: true,
			wantError: "endorsement certificate verification failed",
		},
		{
			name: "forged AK creation signature",
			change: func(_ testing.TB, _ *softwareAK, e *attestuxv1.AttestationEvidence) {
				e.AkCreateSignature[len(e.AkCreateSignature)-1] ^= 0xff
			},
			wantError: "attestation key is not TPM-created",
		},
		// These attributes stop host-chosen digests and keep the private key in the TPM.
		{
			name:       "AK not restricted",
			attributes: legacytpm2.FlagSignerDefault &^ legacytpm2.FlagRestricted,
			wantError:  "attestation key is not TPM-created",
		},
		{
			name:       "AK not fixed to the TPM",
			attributes: legacytpm2.FlagSignerDefault &^ legacytpm2.FlagFixedTPM,
			wantError:  "attestation key is not TPM-created",
		},
		{
			name:       "AK not fixed to its parent",
			attributes: legacytpm2.FlagSignerDefault &^ legacytpm2.FlagFixedParent,
			wantError:  "attestation key is not TPM-created",
		},
		{
			name:       "AK sensitive data supplied by the host",
			attributes: legacytpm2.FlagSignerDefault &^ legacytpm2.FlagSensitiveDataOrigin,
			wantError:  "attestation key is not TPM-created",
		},
		{
			name: "creation proof for another key",
			change: func(t testing.TB, ak *softwareAK, e *attestuxv1.AttestationEvidence) {
				e.AkCreateAttestation, e.AkCreateSignature = ak.creationProof(t, newSoftwareAK(t).name(t), e.AkCreateData)
			},
			wantError: "attestation key is not TPM-created",
		},
		{
			name: "quote presented as the creation proof",
			change: func(_ testing.TB, _ *softwareAK, e *attestuxv1.AttestationEvidence) {
				e.AkCreateAttestation, e.AkCreateSignature = e.PcrBanks[0].Quote.Quote, e.PcrBanks[0].Quote.Signature
			},
			wantError: "attestation key is not TPM-created",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEndorsementCertificateFixture(t)
			ak := newSoftwareAK(t)
			if test.attributes != 0 {
				ak.public.Attributes = test.attributes
			}
			evidence, nonce := softwareEvidenceWithFixture(t, fixture, ak)
			if test.change != nil {
				test.change(t, ak, evidence)
			}
			raw := marshalEvidence(t, evidence)
			policy := fixture.policy()
			if test.untrusted {
				policy.trust = certificateTrust{roots: x509.NewCertPool()}
			}
			session, err := prepareVerificationWithPolicies(raw, nonce, []verificationPolicy{policy}, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			report := session.Report()
			if session.ActivationChallenge() != nil || report.DeviceId == "" || describesTrust(report) ||
				len(report.Pcrs) != attestation.AttestedPCRCount || len(report.Events) != 0 ||
				!containsMessage(report.Errors, test.wantError) {
				t.Fatalf(
					"rejected report: device %q, %d PCRs, %d events, errors %q; want an identified device, no trust facts, no replay, and %q",
					report.DeviceId,
					len(report.Pcrs),
					len(report.Events),
					report.Errors,
					test.wantError,
				)
			}
		})
	}
}

func TestPrepareVerificationUsesTheNuvotonPolicy(t *testing.T) {
	raw, nonce, _ := softwareEvidence(t)
	session, err := PrepareVerification(raw, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Cancel()
	report := session.Report()
	// The fixture has fixed dates, so the exact chain error depends on when this runs.
	if session.ActivationChallenge() != nil || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "Nuvoton: EK certificate 0: verify endorsement certificate: x509:") {
		t.Fatalf("test-CA evidence under the production policies: %v", report)
	}
	policies := runtimeVerificationPolicies()
	if len(policies) == 0 || policies[0].id != attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON ||
		!policies[0].trust.roots.Equal(nuvotonTrust.roots) ||
		!policies[0].trust.intermediates.Equal(nuvotonTrust.intermediates) ||
		!strings.Contains(policies[0].limitation, "revocation") {
		t.Fatalf("runtime policies = %+v, want Nuvoton first with its bundled anchors", policies)
	}
}

func TestPrepareVerificationDisclosesAnIncompleteEventLog(t *testing.T) {
	banks := []attest.HashAlg{attest.HashSHA256}
	header := cryptoAgileEventLogHeader(t, banks)
	for _, test := range []struct {
		name    string
		log     []byte
		omitted uint32
		warning string
	}{
		{"unparsable log", header[:len(header)-1], 0, "event log could not be parsed"},
		{
			"invalid PCR index",
			cryptoAgileEventLog(t, banks, logEvent{pcrIndex: attestation.MaxPCRCount, eventType: 5}),
			1,
			"invalid PCR index",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEndorsementCertificateFixture(t)
			evidence, nonce := softwareEvidenceWithFixture(t, fixture, nil)
			evidence.EventLog = test.log
			raw := marshalEvidence(t, evidence)
			session, err := prepareVerificationWithPolicies(raw, nonce, []verificationPolicy{fixture.policy()}, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			report, err := session.finishActivation(bytes.Clone(session.expectedSecret), "")
			if err != nil {
				t.Fatalf("%v: %q", err, session.Report().Errors)
			}
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED ||
				!report.EventLogIncomplete || report.OmittedEventCount != test.omitted ||
				len(report.Events) != 0 || !containsMessage(report.Warnings, test.warning) {
				t.Fatalf(
					"status %v, incomplete=%v, omitted %d, %d events, warnings %q; want a verified report that discloses %q",
					report.Status,
					report.EventLogIncomplete,
					report.OmittedEventCount,
					len(report.Events),
					report.Warnings,
					test.warning,
				)
			}
		})
	}
}

func TestPrepareVerificationLifecycleInSoftware(t *testing.T) {
	session := newActivationTestSession(t)
	challenge := session.ActivationChallenge()
	report := session.Report()
	if len(report.Errors) != 0 ||
		report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION ||
		describesTrust(report) || !containsMessage(report.Limitations, "descriptive metadata") ||
		len(report.Pcrs) != attestation.AttestedPCRCount || len(report.Warnings) != 0 {
		t.Fatalf("unexpected pending report: %v", report)
	}
	verified, err := session.finishActivation(bytes.Clone(session.expectedSecret), "")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED ||
		verified.TrustPolicy != attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON ||
		!bytes.Equal(verified.EndorsementKeySha256, challenge.EndorsementKeySha256) ||
		!containsMessage(verified.Limitations, "test policy limitation") {
		t.Fatalf("verified report %v; want the policy, its limitation and the activated EK", verified)
	}
	if _, err := CompletionForReport(verified); err != nil {
		t.Fatalf("verified report cannot complete: %v", err)
	}
}

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

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/core/verifier/testtrust"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/encoding/protowire"
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

func TestRejectActivationClearsTheQuoteChallenge(t *testing.T) {
	session, _, _ := newQuoteTestSession(t)
	nonce := session.expectedQuoteNonce
	report, err := session.RejectActivation()
	if err != nil {
		t.Fatal(err)
	}
	if report.Status !=
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!slices.Equal(report.Errors, []string{"TPM credential activation failed: prover reported credential activation failure"}) {
		t.Fatalf("unexpected rejected report: %v", report)
	}
	requireActivationFinished(t, session, nonce)
}

func TestRejectEvidenceReportsAttestationFailure(t *testing.T) {
	session, _, _ := newQuoteTestSession(t)
	nonce := session.expectedQuoteNonce
	initial := session.Report()
	report, err := session.RejectEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!slices.Equal(report.Errors, []string{"prover reported attestation failure"}) || describesTrust(report) ||
		!bytes.Equal(report.EvidenceSha256, initial.EvidenceSha256) {
		t.Fatalf("incorrect attestation-failure report: %v", report)
	}
	requireActivationFinished(t, session, nonce)
}

func TestPrepareVerificationReportsInvalidKeys(t *testing.T) {
	e := attestationtest.MinimallyShapedEvidence()
	e.Keys.EndorsementKeys = nil
	session := PrepareVerification(marshalHello(t, e.Keys))
	if report := session.Report(); report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || !containsMessage(report.Errors, "invalid endorsement-key count") {
		t.Fatalf("invalid keys were accepted: %v", report)
	}
}

func TestPrepareVerificationRejectsEmptyHello(t *testing.T) {
	session := PrepareVerification(nil)
	report := session.Report()
	if session.ActivationChallenge() != nil || len(report.Errors) != 1 ||
		!strings.Contains(report.Errors[0], "size 0 is outside permitted range") {
		t.Fatalf("empty hello was not rejected by size: %v", report)
	}
}

func TestPrepareVerificationHelloSizeBoundary(t *testing.T) {
	fixture := newEndorsementCertificateFixture(t)
	evidence := softwareEvidenceWithFixture(t, fixture, nil)
	hello := marshalHello(t, evidence.Keys)
	for _, test := range []struct {
		name     string
		size     int
		accepted bool
	}{
		{"below limit", attestation.MaxControlMessageSize - 1, true},
		{"at limit", attestation.MaxControlMessageSize, true},
		{"above limit", attestation.MaxControlMessageSize + 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Pad with a valid unknown field; the keys and their proofs stay intact.
			paddingSize := test.size - len(hello) - protowire.SizeTag(100) - protowire.SizeVarint(uint64(test.size))
			raw := protowire.AppendTag(bytes.Clone(hello), 100, protowire.BytesType)
			raw = protowire.AppendBytes(raw, make([]byte, paddingSize))
			if len(raw) != test.size {
				t.Fatalf("padded hello size = %d, want %d", len(raw), test.size)
			}
			session := prepareVerificationWithPolicies(raw, []verificationPolicy{fixture.policy()}, fixture.now)
			defer session.Cancel()
			report := session.Report()
			if sum := sha256.Sum256(raw); !bytes.Equal(report.EvidenceSha256, sum[:]) {
				t.Fatal("report did not hash the complete padded hello")
			}
			if test.accepted {
				if session.ActivationChallenge() == nil || len(report.Errors) != 0 ||
					report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION {
					t.Fatalf("hello of %d bytes did not reach pending activation: %v", test.size, report)
				}
			} else {
				want := fmt.Sprintf("malformed attestation hello: size %d is outside permitted range", test.size)
				if session.ActivationChallenge() != nil ||
					report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
					!slices.Equal(report.Errors, []string{want}) {
					t.Fatalf("hello of %d bytes was not rejected by size: %v", test.size, report)
				}
			}
		})
	}
}

func TestPrepareVerificationRejectsHelloWithoutKeys(t *testing.T) {
	// A future optional field makes the hello nonempty without supplying keys.
	raw := []byte{0x12, 1, 0x55}
	session := PrepareVerification(raw)
	report := session.Report()
	if session.ActivationChallenge() != nil || report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
		!containsMessage(report.Errors, "missing attestation keys") {
		t.Fatalf("hello without keys was not rejected: %v", report)
	}
	if _, err := CompletionForReport(report); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); !bytes.Equal(report.EvidenceSha256, sum[:]) {
		t.Fatal("early rejection report did not hash the full raw hello")
	}
}

func TestFailReportBoundsTheDiagnostic(t *testing.T) {
	report := &resultv1.VerificationReport{}
	failReport(report, "%s", strings.Repeat("e", maxDiagnosticMessageBytes+1))
	if got := len(report.Errors[0]); got != maxDiagnosticMessageBytes+len("...") {
		t.Fatalf("diagnostic length = %d, want the %d byte cap plus an ellipsis", got, maxDiagnosticMessageBytes)
	}
}

func TestPrepareVerificationDoesNotExposeTheExpectedNonce(t *testing.T) {
	session, _, _ := newQuoteTestSession(t)
	defer session.Cancel()
	wire, err := proto.Marshal(session.ActivationChallenge())
	if err != nil {
		t.Fatal(err)
	}
	if len(session.expectedQuoteNonce) != sha256.Size || bytes.Contains(wire, session.expectedQuoteNonce) {
		t.Fatal("activation challenge exposes its quote nonce")
	}
}

func TestCompleteEvidenceConsumesMalformedResponses(t *testing.T) {
	for _, raw := range [][]byte{nil, {0xff}, make([]byte, attestation.MaxEvidenceSize+1)} {
		session, _, _ := newQuoteTestSession(t)
		nonce := session.expectedQuoteNonce
		report, err := session.CompleteEvidence(raw)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || !bytes.Equal(report.EvidenceSha256, sum[:]) {
			t.Fatalf("malformed evidence accepted: %v", report)
		}
		requireActivationFinished(t, session, nonce)
	}
}

// Build keys and PCRs with PCR 7 extended for the log; quoteResponse signs them later.
// A nil ak gets a fresh key.
func softwareEvidenceWithFixture(
	t testing.TB,
	fixture *endorsementCertificateFixture,
	ak *softwareAK,
	events ...logEvent,
) *attestuxv1.AttestationEvidence {
	t.Helper()
	if ak == nil {
		ak = newSoftwareAK(t)
	}
	evidence := ak.unquotedEvidence(t)
	evidence.PcrBanks[0].Pcrs[7].Digest = extendedSHA256PCR(events...)
	evidence.Keys.EndorsementKeys = []*attestuxv1.EndorsementKey{fixture.issue(t, 2, nil)}
	evidence.EventLog = cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, events...)
	return evidence
}

func (fixture *endorsementCertificateFixture) policy() verificationPolicy {
	return verificationPolicy{
		id:         attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		limitation: "test policy limitation",
		trust:      certificateTrust{roots: fixture.roots},
	}
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
	results := []*resultv1.PcrResult{
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
	evidence := softwareEvidenceWithFixture(f, fixture, nil)
	f.Add(marshalHello(f, evidence.Keys))
	f.Add([]byte{0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, hello []byte) {
		if len(hello) > 1<<20 {
			t.Skip()
		}
		session := prepareVerificationWithPolicies(hello, []verificationPolicy{fixture.policy()}, fixture.now)
		defer session.Cancel()
		report := session.Report()
		requireReportIntegrity(t, report, hello)
		if (session.ActivationChallenge() != nil) != (len(report.Errors) == 0) {
			t.Fatal("challenge disagrees with report")
		}
		if len(report.Pcrs) != 0 || describesTrust(report) || report.DeviceId != "" {
			t.Fatal("discovery made unproven claims")
		}
		if session.ActivationChallenge() == nil {
			if _, err := CompletionForReport(report); err != nil {
				t.Fatalf("rejected hello cannot produce a completion: %v", err)
			}
		} else if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION ||
			len(session.expectedQuoteNonce) != sha256.Size {
			t.Fatalf("invalid pending activation: %v", report)
		}
		nonce := session.expectedQuoteNonce
		session.Cancel()
		requireActivationFinished(t, session, nonce)
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

func TestPrepareVerificationRejectsUntrustedKeysWithoutAttribution(t *testing.T) {
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
			name: "trailing AK public data",
			change: func(_ testing.TB, _ *softwareAK, e *attestuxv1.AttestationEvidence) {
				e.Keys.AttestationPublic = append(e.Keys.AttestationPublic, 0)
			},
			wantError: "parse attestation public key: " + attestation.ErrNonCanonicalAKPublic.Error(),
		},
		{
			name: "forged AK creation signature",
			change: func(_ testing.TB, _ *softwareAK, e *attestuxv1.AttestationEvidence) {
				e.Keys.AkCreateSignature[len(e.Keys.AkCreateSignature)-1] ^= 0xff
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
				e.Keys.AkCreateAttestation, e.Keys.AkCreateSignature = ak.creationProof(t, newSoftwareAK(t).name(t), e.Keys.AkCreateData)
			},
			wantError: "attestation key is not TPM-created",
		},
		{
			name: "quote presented as the creation proof",
			change: func(t testing.TB, ak *softwareAK, e *attestuxv1.AttestationEvidence) {
				selection := allAttestedPCRs()
				quote := ak.quoteEvidence(t, nil, selection, zeroPCRComposite(selection)).PcrBanks[0].Quote
				e.Keys.AkCreateAttestation, e.Keys.AkCreateSignature = quote.Quote, quote.Signature
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
			evidence := softwareEvidenceWithFixture(t, fixture, ak)
			if test.change != nil {
				test.change(t, ak, evidence)
			}
			raw := marshalHello(t, evidence.Keys)
			policy := fixture.policy()
			if test.untrusted {
				policy.trust = certificateTrust{roots: x509.NewCertPool()}
			}
			session := prepareVerificationWithPolicies(raw, []verificationPolicy{policy}, fixture.now)
			report := session.Report()
			if session.ActivationChallenge() != nil || report.DeviceId != "" || describesTrust(report) ||
				len(report.Pcrs) != 0 || len(report.Events) != 0 ||
				!containsMessage(report.Errors, test.wantError) {
				t.Fatalf(
					"rejected report: device %q, %d PCRs, %d events, errors %q; want no device attribution, no trust facts, no replay, and %q",
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
	fixture := newEndorsementCertificateFixture(t)
	e := softwareEvidenceWithFixture(t, fixture, nil)
	session := PrepareVerification(marshalHello(t, e.Keys))
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

func TestCompleteEvidenceDisclosesAnIncompleteEventLog(t *testing.T) {
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
			session, ak, evidence := newQuoteTestSession(t)
			evidence.EventLog = test.log
			raw := quoteResponse(t, ak, evidence, session.expectedQuoteNonce)
			report, err := session.CompleteEvidence(raw)
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
	session, ak, evidence := newQuoteTestSession(t)
	wantDeviceID, err := attestation.DeviceID(evidence.Keys.AttestationPublic)
	if err != nil {
		t.Fatal(err)
	}
	challenge := session.ActivationChallenge()
	pending := session.Report()
	if pending.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION || pending.DeviceId != "" || len(pending.Pcrs) != 0 || describesTrust(pending) {
		t.Fatalf("discovery makes unproven claims: %v", pending)
	}
	nonce := session.expectedQuoteNonce
	raw := quoteResponse(t, ak, evidence, nonce)
	verified, err := session.CompleteEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED || verified.DeviceId != wantDeviceID || !bytes.Equal(verified.EndorsementKeySha256, challenge.EndorsementKeySha256) || !containsMessage(verified.Limitations, "test policy limitation") {
		t.Fatalf("unexpected verified report: %v", verified)
	}
	if _, err := CompletionForReport(verified); err != nil {
		t.Fatal(err)
	}
	snapshot := session.Report()
	verified.Pcrs[0].Pcr.Digest[0] ^= 0xff
	if !proto.Equal(snapshot, session.Report()) {
		t.Fatal("caller changed session report")
	}
	requireActivationFinished(t, session, nonce)
}

func newQuoteTestSession(t *testing.T) (*VerificationSession, *softwareAK, *attestuxv1.AttestationEvidence) {
	t.Helper()
	fixture := newEndorsementCertificateFixture(t)
	ak := newSoftwareAK(t)
	evidence := softwareEvidenceWithFixture(t, fixture, ak)
	session := prepareVerificationWithPolicies(marshalHello(t, evidence.Keys), []verificationPolicy{fixture.policy()}, fixture.now)
	if session.ActivationChallenge() == nil {
		t.Fatalf("keys were rejected: %v", session.Report())
	}
	return session, ak, evidence
}

func quoteResponse(t testing.TB, ak *softwareAK, evidence *attestuxv1.AttestationEvidence, nonce []byte) []byte {
	t.Helper()
	out := proto.Clone(evidence).(*attestuxv1.AttestationEvidence)
	composite := sha256.New()
	for _, pcr := range out.PcrBanks[0].Pcrs {
		composite.Write(pcr.Digest)
	}
	out.PcrBanks[0].Quote = ak.quoteEvidence(t, nonce, allAttestedPCRs(), composite.Sum(nil)).PcrBanks[0].Quote
	return marshalEvidence(t, out)
}

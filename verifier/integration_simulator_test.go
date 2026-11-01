//go:build tpmsimulator && cgo

package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
)

func TestSimulatedTPMEndToEnd(t *testing.T) {
	sim, tpm := attestationtest.NewSimulatedTPM(t)
	ak, err := tpm.NewAK(&attest.AKConfig{Algorithm: attest.ECDSA})
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close(tpm)

	banks, err := tpm.PCRBanks()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(banks, attest.HashSHA256) {
		t.Fatal("SHA-256 bank missing")
	}
	eventData := []byte("AttesTux simulator boot event")
	eventLog := cryptoAgileEventLog(t, banks, logEvent{pcrIndex: 7, eventType: 5, data: eventData})
	if err := tpm2.PCRExtend(sim, tpmutil.Handle(7), tpm2.AlgSHA256, hashBytes(crypto.SHA256, eventData), ""); err != nil {
		t.Fatal(err)
	}
	eks, err := tpm.EKs()
	if err != nil || len(eks) == 0 {
		t.Fatalf("EK discovery: %v", err)
	}
	fixture := newEndorsementCertificateFixture(t)
	keys := simulatorAttestationKeys(ak, fixture.issueFor(t, 2, eks[0].Public, nil))
	policies := []verificationPolicy{{id: attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR, limitation: SimulatorLimitation, trust: certificateTrust{roots: fixture.roots}}}
	prepare := func(t *testing.T, k *attestuxv1.AttestationKeys) *VerificationSession {
		t.Helper()
		raw := marshalHello(t, k)
		session := prepareVerificationWithPolicies(raw, policies, fixture.now)
		t.Cleanup(session.Cancel)
		return session
	}
	recoverSecret := func(t *testing.T, session *VerificationSession) []byte {
		t.Helper()
		challenge := session.ActivationChallenge()
		if challenge == nil {
			t.Fatalf("keys rejected: %v", session.Report())
		}
		secret, err := ak.ActivateCredentialWithEK(tpm, attest.EncryptedCredential{Credential: challenge.Credential, Secret: challenge.EncryptedSecret}, eks[0])
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	collect := func(t *testing.T, nonce []byte) *attestuxv1.AttestationEvidence {
		t.Helper()
		quote, pcrs, err := attestation.QuoteSHA256PCRs(tpm, ak, nonce)
		if err != nil {
			t.Fatal(err)
		}
		e := &attestuxv1.AttestationEvidence{
			Keys: proto.Clone(keys).(*attestuxv1.AttestationKeys), EventLog: bytes.Clone(eventLog),
			PcrBanks: []*attestuxv1.PcrBankEvidence{{HashAlgorithm: attestation.TPMAlgSHA256, Quote: &attestuxv1.Quote{Quote: quote.Quote, Signature: quote.Signature}}},
		}
		for _, pcr := range pcrs {
			e.PcrBanks[0].Pcrs = append(e.PcrBanks[0].Pcrs, &attestuxv1.Pcr{Index: uint32(pcr.Index), Digest: pcr.Digest})
		}
		return e
	}
	session := prepare(t, keys)
	challenge := session.ActivationChallenge()
	secret := recoverSecret(t, session)
	nonce := attestation.ActivationQuoteNonce(secret)
	evidence := collect(t, nonce)
	raw := marshalEvidence(t, evidence)
	if bytes.Contains(raw, secret) {
		t.Fatal("evidence contains the plaintext activation secret")
	}
	quote, err := tpm2.DecodeAttestationData(evidence.PcrBanks[0].Quote.Quote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(quote.ExtraData, nonce) || bytes.Equal(quote.ExtraData, secret) {
		t.Fatal("quote must contain SHA-256(secret)")
	}
	clear(secret)
	expectedNonce := session.expectedQuoteNonce
	report, err := session.CompleteEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED || len(report.Errors) != 0 || len(report.Warnings) != 0 || len(report.Pcrs) != 16 || len(report.Events) != 1 {
		t.Fatalf("verification failed: %v", report)
	}
	if !bytes.Equal(report.EndorsementKeySha256, challenge.EndorsementKeySha256) || !containsMessage(report.Limitations, SimulatorLimitation) || !containsMessage(report.Limitations, "descriptive metadata") {
		t.Fatalf("missing trust facts: %v", report)
	}
	for _, digest := range report.Events[0].Digests {
		want := resultv1.ReplayState_REPLAY_STATE_UNVERIFIED
		if digest.HashAlgorithm == attestation.TPMAlgSHA256 {
			want = resultv1.ReplayState_REPLAY_STATE_VERIFIED
		}
		if digest.State != want {
			t.Fatalf("wrong digest state: %v", digest)
		}
	}
	requireActivationFinished(t, session, expectedNonce)

	t.Run("replay into another challenge", func(t *testing.T) {
		next := prepare(t, keys)
		if bytes.Equal(next.expectedQuoteNonce, nonce) {
			t.Fatal("activation challenge reused its nonce")
		}
		rejected, err := next.CompleteEvidence(raw)
		if err != nil {
			t.Fatal(err)
		}
		if rejected.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED || describesTrust(rejected) {
			t.Fatal("old quote was accepted")
		}
	})
	t.Run("raw secret as quote nonce", func(t *testing.T) {
		next := prepare(t, keys)
		secret := recoverSecret(t, next)
		defer clear(secret)
		rejected, err := next.CompleteEvidence(marshalEvidence(t, collect(t, secret)))
		if err != nil {
			t.Fatal(err)
		}
		if rejected.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED {
			t.Fatal("unhashed secret accepted")
		}
	})
	for _, test := range []struct {
		name    string
		change  func(*attestuxv1.AttestationEvidence)
		warning string
	}{
		{"additional unsupported bank", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks = append(e.PcrBanks, attestationtest.MakeUnsupportedPCRBank(e, 0x000d, sha512.Size))
		}, "ignored unsupported PCR banks: SHA-512"},
		{"mutated event log", func(e *attestuxv1.AttestationEvidence) {
			offset := bytes.Index(e.EventLog, hashBytes(crypto.SHA256, eventData))
			e.EventLog[offset] ^= 0xff
		}, "event-log replay failed"},
		{"suppressed event log", func(e *attestuxv1.AttestationEvidence) { e.EventLog = cryptoAgileEventLogHeader(t, banks) }, "no extending event covers non-initial PCR 7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := prepare(t, keys)
			secret := recoverSecret(t, next)
			e := collect(t, attestation.ActivationQuoteNonce(secret))
			clear(secret)
			test.change(e)
			report, err := next.CompleteEvidence(marshalEvidence(t, e))
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED || !containsMessage(report.Warnings, test.warning) {
				t.Fatalf("unexpected report: %v", report)
			}
		})
	}
	t.Run("forged AK creation signature", func(t *testing.T) {
		forged := proto.Clone(keys).(*attestuxv1.AttestationKeys)
		forged.AkCreateSignature[len(forged.AkCreateSignature)-1] ^= 0xff
		next := prepare(t, forged)
		if next.ActivationChallenge() != nil || !containsMessage(next.Report().Errors, "attestation key is not TPM-created") || len(next.Report().Pcrs) != 0 {
			t.Fatalf("forged key accepted: %v", next.Report())
		}
	})
}

func simulatorAttestationKeys(ak *attest.AK, endorsement *attestuxv1.EndorsementKey) *attestuxv1.AttestationKeys {
	parameters := ak.AttestationParameters()
	return &attestuxv1.AttestationKeys{
		AttestationPublic:   bytes.Clone(parameters.Public),
		AkCreateData:        bytes.Clone(parameters.CreateData),
		AkCreateAttestation: bytes.Clone(parameters.CreateAttestation),
		AkCreateSignature:   bytes.Clone(parameters.CreateSignature),
		EndorsementKeys:     []*attestuxv1.EndorsementKey{proto.Clone(endorsement).(*attestuxv1.EndorsementKey)},
	}
}

func TestCryptoAgileEventLogMatchesTPM2Tools(t *testing.T) {
	tool, err := exec.LookPath("tpm2_eventlog")
	if err != nil {
		t.Skip("tpm2_eventlog is not installed")
	}
	eventLog := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA1, attest.HashSHA256},
		logEvent{
			pcrIndex:  7,
			eventType: 5,
			data:      []byte("AttesTux tpm2_eventlog compatibility event"),
		},
	)
	name := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(name, eventLog, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(tool, name).CombinedOutput()
	if err != nil {
		t.Fatalf("tpm2_eventlog rejected generated log: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("EV_ACTION")) {
		t.Fatalf("tpm2_eventlog output omitted EV_ACTION:\n%s", output)
	}
}

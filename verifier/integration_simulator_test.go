//go:build tpmsimulator && cgo

package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
)

func prepareVerificationWithRoots(
	evidenceBytes,
	expectedNonce []byte,
	roots *x509.CertPool,
	now time.Time,
) (*VerificationSession, error) {
	return prepareVerificationWithPolicies(
		evidenceBytes,
		expectedNonce,
		[]verificationPolicy{{
			id:         attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR,
			limitation: SimulatorLimitation,
			trust:      certificateTrust{roots: roots},
		}},
		now,
	)
}

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
	eventData := []byte("AttesTux simulator boot event")
	eventLog := cryptoAgileEventLog(t, banks, logEvent{
		pcrIndex:  7,
		eventType: 5,
		data:      eventData,
	})
	if !slices.Contains(banks, attest.HashSHA256) {
		t.Fatal("simulator does not allocate SHA-256")
	}
	if err := tpm2.PCRExtend(
		sim,
		tpmutil.Handle(7),
		tpm2.AlgSHA256,
		hashBytes(crypto.SHA256, eventData),
		"",
	); err != nil {
		t.Fatalf("extend SHA-256 bank: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x22}, 32)
	quote, quotedPCRs, err := attestation.QuoteSHA256PCRs(tpm, ak, nonce)
	if err != nil {
		t.Fatal(err)
	}

	parameters := ak.AttestationParameters()
	eks, err := tpm.EKs()
	if err != nil || len(eks) == 0 {
		t.Fatalf("read simulator EK: %v", err)
	}
	roots, ekCertificate, now := simulatorEKCertificate(t, eks[0].Public)
	ekPublic, err := x509.MarshalPKIXPublicKey(eks[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &attestuxv1.AttestationEvidence{
		AttestationPublic:   parameters.Public,
		EventLog:            eventLog,
		AkCreateData:        parameters.CreateData,
		AkCreateAttestation: parameters.CreateAttestation,
		AkCreateSignature:   parameters.CreateSignature,
		EndorsementKeys: []*attestuxv1.EndorsementKey{{
			PublicKey:   ekPublic,
			Certificate: ekCertificate,
		}},
	}
	bank := &attestuxv1.PcrBankEvidence{
		HashAlgorithm: attestation.TPMAlgSHA256,
		Quote: &attestuxv1.Quote{
			Quote:     quote.Quote,
			Signature: quote.Signature,
		},
	}
	evidence.PcrBanks = []*attestuxv1.PcrBankEvidence{bank}
	for _, pcr := range quotedPCRs {
		if pcr.DigestAlg != crypto.SHA256 {
			t.Fatalf("unexpected PCR hash algorithm %v", pcr.DigestAlg)
		}
		bank.Pcrs = append(bank.Pcrs, &attestuxv1.Pcr{
			Index: uint32(pcr.Index), Digest: pcr.Digest,
		})
	}
	prepare := func(
		t *testing.T,
		evidence *attestuxv1.AttestationEvidence,
		nonce []byte,
		accepted bool,
	) (*VerificationSession, *attestuxv1.VerificationReport) {
		t.Helper()
		verification, err := prepareVerificationWithRoots(marshalEvidence(t, evidence), nonce, roots, now)
		if err != nil {
			t.Fatal(err)
		}
		report := verification.Report()
		if challenged := verification.ActivationChallenge() != nil; challenged != accepted ||
			(len(report.Errors) == 0) != accepted {
			t.Fatalf(
				"activation challenge issued = %v, errors = %v, want accepted = %v",
				challenged,
				report.Errors,
				accepted,
			)
		}
		return verification, report
	}

	clone := func() *attestuxv1.AttestationEvidence {
		return proto.Clone(evidence).(*attestuxv1.AttestationEvidence)
	}
	verification, _ := prepare(t, evidence, nonce, true)
	activationChallenge := verification.ActivationChallenge()
	secret, err := ak.ActivateCredentialWithEK(
		tpm,
		attest.EncryptedCredential{
			Credential: activationChallenge.Credential,
			Secret:     activationChallenge.EncryptedSecret,
		},
		eks[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := proto.Marshal(&attestuxv1.CredentialActivationResponse{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	report, err := verification.CompleteActivationBytes(response)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status !=
		attestuxv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED {
		t.Fatalf("verification failed: %v", report.Errors)
	}
	if !bytes.Equal(
		report.EndorsementKeySha256,
		activationChallenge.EndorsementKeySha256,
	) {
		t.Fatalf(
			"report EK hash %x does not match the activation challenge %x",
			report.EndorsementKeySha256,
			activationChallenge.EndorsementKeySha256,
		)
	}
	if !containsMessage(report.Limitations, SimulatorLimitation) {
		t.Fatalf("missing policy limitation: %v", report.Limitations)
	}
	if !containsMessage(report.Limitations, "descriptive metadata") {
		t.Fatalf("missing event-metadata limitation: %v", report.Limitations)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("clean scan reported warnings: %v", report.Warnings)
	}
	if len(report.Pcrs) != len(quotedPCRs) {
		t.Fatalf("reported %d PCRs, want %d", len(report.Pcrs), len(quotedPCRs))
	}
	for _, result := range report.Pcrs {
		if result.HashAlgorithm != attestation.TPMAlgSHA256 {
			t.Fatalf("PCR result algorithm = %#x, want SHA-256", result.HashAlgorithm)
		}
	}
	if len(report.Events) != 1 || len(report.Events[0].Digests) == 0 {
		t.Fatalf("reported events = %#v, want event digests", report.Events)
	}
	foundSHA256 := false
	for _, digest := range report.Events[0].Digests {
		if digest.HashAlgorithm == attestation.TPMAlgSHA256 {
			foundSHA256 = true
			if digest.State !=
				attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED {
				t.Fatalf("SHA-256 event digest was not verified: %v", digest)
			}
		} else if digest.State !=
			attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED {
			t.Fatalf("unsupported event digest made a security claim: %v", digest)
		}
	}
	if !foundSHA256 {
		t.Fatal("normalized event omitted its SHA-256 digest")
	}
	deviceID := report.DeviceId

	t.Run("forged AK creation signature", func(t *testing.T) {
		forged := clone()
		forged.AkCreateSignature = bytes.Clone(forged.AkCreateSignature)
		forged.AkCreateSignature[len(forged.AkCreateSignature)-1] ^= 0xff

		_, report := prepare(t, forged, nonce, false)

		if report.DeviceId == "" || len(report.Pcrs) == 0 || len(report.Events) != 0 ||
			!containsMessage(report.Errors, "attestation key is not TPM-created") {
			t.Fatalf(
				"rejected AK report: device %q, %d PCRs, %d events, errors %q; want an identified device, no replay, and the AK blamed",
				report.DeviceId,
				len(report.Pcrs),
				len(report.Events),
				report.Errors,
			)
		}
	})

	t.Run("additional unsupported bank", func(t *testing.T) {
		future := clone()
		futureBank := attestationtest.MakeUnsupportedPCRBank(future, 0x000d, sha512.Size)
		future.PcrBanks = append(future.PcrBanks, futureBank)

		_, report := prepare(t, future, nonce, true)

		if !containsMessage(report.Warnings, "ignored unsupported PCR banks: SHA-512") {
			t.Fatalf("missing unsupported-bank warning: %v", report.Warnings)
		}
	})

	t.Run("mutated nonce", func(t *testing.T) {
		mutated := bytes.Clone(nonce)
		mutated[0] ^= 0xff

		prepare(t, evidence, mutated, false)
	})

	t.Run("mutated event log", func(t *testing.T) {
		mutated := clone()
		mutated.EventLog = bytes.Clone(mutated.EventLog)
		digestOffset := bytes.Index(mutated.EventLog, hashBytes(crypto.SHA256, eventData))
		if digestOffset < 0 {
			t.Fatal("generated event log omitted the SHA-256 event digest")
		}
		mutated.EventLog[digestOffset] ^= 0xff

		_, report := prepare(t, mutated, nonce, true)

		if len(report.Events) != 1 {
			t.Fatalf("report omitted parsed events: got %d", len(report.Events))
		}
		if !containsMessage(report.Warnings, "event-log replay failed") {
			t.Fatalf("missing event-log warning: %v", report.Warnings)
		}
		for _, result := range report.Pcrs {
			if result.Pcr.Index == 7 && result.EventLogReplayed {
				t.Fatal("mutated event log was replayed for SHA-256 PCR 7")
			}
		}
	})

	t.Run("suppressed event log", func(t *testing.T) {
		suppressed := clone()
		suppressed.EventLog = cryptoAgileEventLogHeader(t, banks)

		_, report := prepare(t, suppressed, nonce, true)

		if !containsMessage(report.Warnings, "no extending event covers non-initial PCR 7") {
			t.Fatalf("missing replay-coverage warning: %v", report.Warnings)
		}
		for _, result := range report.Pcrs {
			if result.Pcr.Index == 7 && result.EventLogReplayed {
				t.Fatal("PCR 7 was marked replayed without an extending event")
			}
		}
	})

	t.Run("trailing AK data", func(t *testing.T) {
		trailing := clone()
		trailing.AttestationPublic = append(
			bytes.Clone(trailing.AttestationPublic),
			0xde, 0xad, 0xbe, 0xef,
		)

		_, report := prepare(t, trailing, nonce, false)

		if report.DeviceId != deviceID {
			t.Fatalf(
				"non-canonical AK changed device ID: got %q, want %q",
				report.DeviceId,
				deviceID,
			)
		}
		if !containsMessage(report.Errors, "trailing or non-canonical data") {
			t.Fatalf("missing canonical-AK error: %v", report.Errors)
		}
	})
}

func simulatorEKCertificate(
	t *testing.T,
	ekPublic crypto.PublicKey,
) (*x509.CertPool, []byte, time.Time) {
	t.Helper()
	fixture := newEndorsementCertificateFixture(t)
	return fixture.roots, fixture.issueFor(t, 2, ekPublic, nil).Certificate, fixture.now
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

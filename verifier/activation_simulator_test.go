//go:build tpmsimulator && cgo

package verifier

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/protocol-go/attestux/v1"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
)

func TestSimulatedTPMActivationRejectsMismatchedKeys(t *testing.T) {
	// The simulator is process-global. Capture the other TPM's public EK and
	// close it before opening our usual fixture, whose hierarchy seed is 42.
	foreignEK := readForeignEKPublic(t)
	_, tpm := attestationtest.NewSimulatedTPM(t)
	eks, err := tpm.EKs()
	if err != nil || len(eks) != 1 {
		t.Fatalf("local TPM EK discovery: keys=%d, error=%v", len(eks), err)
	}
	ek := eks[0]
	if bytes.Equal(marshalActivationPublic(t, ek.Public), marshalActivationPublic(t, foreignEK)) {
		t.Fatal("distinct TPM seeds produced the same endorsement key")
	}
	akA, akB := newSimulatorAK(t, tpm), newSimulatorAK(t, tpm)
	if bytes.Equal(akA.AttestationParameters().Public, akB.AttestationParameters().Public) {
		t.Fatal("the two attestation keys must be distinct")
	}
	fixture := newEndorsementCertificateFixture(t)
	activate := func(ak *attest.AK, session *VerificationSession) ([]byte, error) {
		challenge := session.ActivationChallenge()
		return ak.ActivateCredentialWithEK(tpm, attest.EncryptedCredential{
			Credential: challenge.Credential,
			Secret:     challenge.EncryptedSecret,
		}, ek)
	}
	// Positive controls ensure both AK handles can activate credentials with
	// this TPM's EK; handle or authorization failures must not pass this test.
	for _, test := range []struct {
		name string
		ak   *attest.AK
	}{{"matching AK A", akA}, {"matching AK B", akB}} {
		t.Run(test.name, func(t *testing.T) {
			session := prepareActivationSession(t, fixture, test.ak, ek.Public)
			secret, err := activate(test.ak, session)
			defer clear(secret)
			if err != nil {
				t.Fatalf("matching keys failed activation: %v", err)
			}
			if !bytes.Equal(attestation.ActivationQuoteNonce(secret), session.expectedQuoteNonce) {
				t.Fatal("matching keys recovered the wrong activation secret")
			}
		})
	}
	for _, test := range []struct {
		name      string
		public    crypto.PublicKey
		activator *attest.AK
		want      tpm2.ParameterError
	}{
		{"AK B cannot activate AK A credential", ek.Public, akB, tpm2.ParameterError{Code: tpm2.RCIntegrity, Parameter: 1}},
		{"AK A cannot activate a foreign EK credential", foreignEK, akA, tpm2.ParameterError{Code: tpm2.RCValue, Parameter: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := prepareActivationSession(t, fixture, akA, test.public)
			nonce := session.expectedQuoteNonce
			secret, err := activate(test.activator, session)
			defer clear(secret)
			var parameterError tpm2.ParameterError
			if len(secret) != 0 || !errors.As(err, &parameterError) || parameterError != test.want {
				t.Fatalf("mismatched keys returned %d secret bytes and error %v; want %v", len(secret), err, test.want)
			}
			report, err := session.RejectActivation()
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
				report.DeviceId != "" || describesTrust(report) || len(report.Pcrs) != 0 || len(report.Events) != 0 {
				t.Fatalf("failed activation retained trust claims: %v", report)
			}
			requireActivationFinished(t, session, nonce)
		})
	}
}

func readForeignEKPublic(t testing.TB) crypto.PublicKey {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(43)
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	tpm := attest.InjectSimulatedTPMForTest(sim)
	eks, err := tpm.EKs()
	if err != nil || len(eks) != 1 {
		t.Fatalf("foreign TPM EK discovery: keys=%d, error=%v", len(eks), err)
	}
	return eks[0].Public
}

func marshalActivationPublic(t testing.TB, public crypto.PublicKey) []byte {
	t.Helper()
	raw, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newSimulatorAK(t testing.TB, tpm *attest.TPM) *attest.AK {
	t.Helper()
	ak, err := tpm.NewAK(&attest.AKConfig{Algorithm: attest.ECDSA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ak.Close(tpm) })
	return ak
}

func prepareActivationSession(
	t testing.TB,
	fixture *endorsementCertificateFixture,
	ak *attest.AK,
	public crypto.PublicKey,
) *VerificationSession {
	t.Helper()
	keys := simulatorAttestationKeys(ak, fixture.issueFor(t, 2, public, nil))
	raw := marshalHello(t, keys)
	session := prepareVerificationWithPolicies(raw, []verificationPolicy{fixture.policy()}, fixture.now)
	t.Cleanup(session.Cancel)
	// Both the creation proof and EK certificate are valid, even when the
	// keys belong to different TPMs. Activation must establish their binding.
	report := session.Report()
	if session.ActivationChallenge() == nil ||
		report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION ||
		report.DeviceId != "" || describesTrust(report) {
		t.Fatalf("valid key material did not reach pending activation: %v", report)
	}
	return session
}

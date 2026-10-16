package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/attestux/core/attestation"
	"github.com/attestux/core/attestation/attestationtest"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// tpmGeneratedMagic starts every structure a TPM signs with a restricted key.
const tpmGeneratedMagic = 0xff544347

// softwareAK can sign like a TPM. Activation is what tells them apart.
type softwareAK struct {
	key    *ecdsa.PrivateKey
	public legacytpm2.Public
}

func newSoftwareAK(t testing.TB) *softwareAK {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &softwareAK{
		key: key,
		public: legacytpm2.Public{
			Type:       legacytpm2.AlgECC,
			NameAlg:    legacytpm2.AlgSHA256,
			Attributes: legacytpm2.FlagSignerDefault,
			ECCParameters: &legacytpm2.ECCParams{
				Sign: &legacytpm2.SigScheme{
					Alg:  legacytpm2.AlgECDSA,
					Hash: legacytpm2.AlgSHA256,
				},
				CurveID: legacytpm2.CurveNISTP256,
				Point: legacytpm2.ECPoint{
					XRaw: key.X.FillBytes(make([]byte, 32)),
					YRaw: key.Y.FillBytes(make([]byte, 32)),
				},
			},
		},
	}
}

func (ak *softwareAK) encodedPublic(t testing.TB) []byte {
	t.Helper()
	encoded, err := ak.public.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (ak *softwareAK) name(t testing.TB) legacytpm2.Name {
	t.Helper()
	name, err := ak.public.Name()
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// Use the TPM's magic unless the test asks for a different value.
func (ak *softwareAK) sign(t testing.TB, attestation legacytpm2.AttestationData) (encoded, signature []byte) {
	t.Helper()
	if attestation.Magic == 0 {
		attestation.Magic = tpmGeneratedMagic
	}
	encoded, err := attestation.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := hashBytes(crypto.SHA256, encoded)
	r, s, err := ecdsa.Sign(rand.Reader, ak.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	signature, err = tpmutil.Pack(
		legacytpm2.AlgECDSA,
		legacytpm2.AlgSHA256,
		tpmutil.U16Bytes(r.FillBytes(make([]byte, 32))),
		tpmutil.U16Bytes(s.FillBytes(make([]byte, 32))),
	)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, signature
}

func (ak *softwareAK) creationProof(t testing.TB, name legacytpm2.Name, createData []byte) (attestation, signature []byte) {
	t.Helper()
	return ak.sign(t, legacytpm2.AttestationData{
		Type: legacytpm2.TagAttestCreation,
		AttestedCreationInfo: &legacytpm2.CreationInfo{
			Name:         name,
			OpaqueDigest: hashBytes(crypto.SHA256, createData),
		},
	})
}

func (ak *softwareAK) evidenceForQuote(t testing.TB, quote legacytpm2.AttestationData) *attestuxv1.AttestationEvidence {
	t.Helper()
	createData, err := (&legacytpm2.CreationData{
		PCRSelection:  legacytpm2.PCRSelection{Hash: legacytpm2.AlgSHA256},
		ParentNameAlg: legacytpm2.AlgSHA256,
	}).EncodeCreationData()
	if err != nil {
		t.Fatal(err)
	}
	evidence := attestationtest.MinimallyShapedEvidence()
	evidence.AttestationPublic = ak.encodedPublic(t)
	evidence.AkCreateData = createData
	evidence.AkCreateAttestation, evidence.AkCreateSignature = ak.creationProof(t, ak.name(t), createData)
	quoteBytes, quoteSignature := ak.sign(t, quote)
	evidence.PcrBanks[0].Quote = &attestuxv1.Quote{Quote: quoteBytes, Signature: quoteSignature}
	return evidence
}

func (ak *softwareAK) quoteEvidence(
	t testing.TB,
	nonce []byte,
	selection legacytpm2.PCRSelection,
	pcrDigest []byte,
) *attestuxv1.AttestationEvidence {
	t.Helper()
	return ak.evidenceForQuote(t, legacytpm2.AttestationData{
		Type:      legacytpm2.TagAttestQuote,
		ExtraData: nonce,
		AttestedQuoteInfo: &legacytpm2.QuoteInfo{
			PCRSelection: selection,
			PCRDigest:    pcrDigest,
		},
	})
}

func zeroPCRComposite(selection legacytpm2.PCRSelection) []byte {
	composite := sha256.New()
	for range selection.PCRs {
		composite.Write(make([]byte, sha256.Size))
	}
	return composite.Sum(nil)
}

func allAttestedPCRs() legacytpm2.PCRSelection {
	selected := make([]int, attestation.AttestedPCRCount)
	for index := range selected {
		selected[index] = index
	}
	return legacytpm2.PCRSelection{Hash: legacytpm2.AlgSHA256, PCRs: selected}
}

func TestVerifyQuotedPCRsSelectionCoverage(t *testing.T) {
	for _, test := range []struct {
		name       string
		selection  legacytpm2.PCRSelection
		changeAK   func([]byte) []byte
		identified bool
		wantError  string
	}{
		{
			name:      "no SHA-256 PCR",
			selection: legacytpm2.PCRSelection{Hash: legacytpm2.AlgSHA1},
			wantError: "does not cover SHA-256 PCR",
		},
		{
			name:      "one reported PCR",
			selection: legacytpm2.PCRSelection{Hash: legacytpm2.AlgSHA256, PCRs: []int{0}},
			wantError: "was not included in quote",
		},
		{
			name:      "unparsable AK",
			selection: allAttestedPCRs(),
			changeAK:  func([]byte) []byte { return []byte{9} },
			wantError: "parse attestation public key",
		},
		{
			name:       "trailing AK data",
			selection:  allAttestedPCRs(),
			changeAK:   func(akPublic []byte) []byte { return append(akPublic, 0) },
			identified: true,
			wantError:  "trailing or non-canonical data",
		},
		{name: "all attested PCRs", selection: allAttestedPCRs()},
	} {
		t.Run(test.name, func(t *testing.T) {
			nonce := bytes.Repeat([]byte{byte(len(test.selection.PCRs))}, 32)
			evidence := newSoftwareAK(t).quoteEvidence(t, nonce, test.selection, zeroPCRComposite(test.selection))
			evidence.PcrBanks = append(
				[]*attestuxv1.PcrBankEvidence{attestationtest.MakeUnsupportedPCRBank(evidence, attestation.TPMAlgSHA1, 20)},
				evidence.PcrBanks...,
			)
			if test.changeAK != nil {
				evidence.AttestationPublic = test.changeAK(evidence.AttestationPublic)
			}
			deviceID, pcrs, results, err := verifyQuotedPCRs(evidence, nonce)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) || (deviceID != "") != test.identified {
					t.Fatalf("got device %q, error %v; want %q, identified %v", deviceID, err, test.wantError, test.identified)
				}
				report, _ := buildQuoteReportAndPCRs(evidence, nonce)
				if report.Status != attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED ||
					report.DeviceId != deviceID || len(report.Warnings) != 0 || !containsMessage(report.Errors, test.wantError) {
					t.Fatalf("rejected report = %v; want device %q, no warnings, and error %q", report, deviceID, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected a fully covering quote: %v", err)
			}
			if deviceID == "" ||
				len(pcrs) != attestation.AttestedPCRCount || len(results) != attestation.AttestedPCRCount {
				t.Fatalf("got device %q, %d PCRs and %d results", deviceID, len(pcrs), len(results))
			}
		})
	}
}

func TestVerifyQuotedPCRsRejectsForgedQuotes(t *testing.T) {
	expected := hashBytes(crypto.SHA256, []byte("expected nonce"))
	selection := allAttestedPCRs()
	quoteOver := func(nonce []byte) legacytpm2.AttestationData {
		return legacytpm2.AttestationData{
			Type:      legacytpm2.TagAttestQuote,
			ExtraData: nonce,
			AttestedQuoteInfo: &legacytpm2.QuoteInfo{
				PCRSelection: selection,
				PCRDigest:    zeroPCRComposite(selection),
			},
		}
	}
	forged := func(change func(testing.TB, *softwareAK, *legacytpm2.AttestationData)) func(testing.TB) *attestuxv1.AttestationEvidence {
		return func(t testing.TB) *attestuxv1.AttestationEvidence {
			ak := newSoftwareAK(t)
			quote := quoteOver(expected)
			change(t, ak, &quote)
			return ak.evidenceForQuote(t, quote)
		}
	}
	overNonce := func(nonce []byte) func(testing.TB) *attestuxv1.AttestationEvidence {
		return forged(func(_ testing.TB, _ *softwareAK, quote *legacytpm2.AttestationData) { quote.ExtraData = nonce })
	}
	for _, test := range []struct {
		name      string
		evidence  func(testing.TB) *attestuxv1.AttestationEvidence
		wantError string
	}{
		{
			name: "wrong magic",
			evidence: forged(func(_ testing.TB, _ *softwareAK, quote *legacytpm2.AttestationData) {
				quote.Magic = tpmGeneratedMagic - 1
			}),
			wantError: "incorrect magic value",
		},
		{
			name: "creation structure as the quote",
			evidence: forged(func(t testing.TB, ak *softwareAK, quote *legacytpm2.AttestationData) {
				quote.Type = legacytpm2.TagAttestCreation
				quote.AttestedQuoteInfo = nil
				quote.AttestedCreationInfo = &legacytpm2.CreationInfo{Name: ak.name(t), OpaqueDigest: make([]byte, sha256.Size)}
			}),
			wantError: "attestation isn't a quote",
		},
		{
			name: "certify structure as the quote",
			evidence: forged(func(t testing.TB, ak *softwareAK, quote *legacytpm2.AttestationData) {
				quote.Type = legacytpm2.TagAttestCertify
				quote.AttestedQuoteInfo = nil
				quote.AttestedCertifyInfo = &legacytpm2.CertifyInfo{Name: ak.name(t), QualifiedName: ak.name(t)}
			}),
			wantError: "attestation isn't a quote",
		},
		{
			name: "quote over other PCR values",
			evidence: forged(func(_ testing.TB, _ *softwareAK, quote *legacytpm2.AttestationData) {
				quote.AttestedQuoteInfo.PCRDigest = hashBytes(crypto.SHA256, []byte("other values"))
			}),
			wantError: "quote digest didn't match",
		},
		{
			name: "quote signed by another key",
			evidence: func(t testing.TB) *attestuxv1.AttestationEvidence {
				evidence := newSoftwareAK(t).evidenceForQuote(t, quoteOver(expected))
				evidence.AttestationPublic = newSoftwareAK(t).encodedPublic(t)
				return evidence
			},
			wantError: "invalid quote signature",
		},
		{name: "another nonce", evidence: overNonce(hashBytes(crypto.SHA256, []byte("another nonce"))), wantError: "nonce"},
		{name: "20-byte prefix of the nonce", evidence: overNonce(expected[:20]), wantError: "nonce"},
		{name: "SHA-1 of the nonce", evidence: overNonce(hashBytes(crypto.SHA1, expected)), wantError: "nonce"},
		{name: "SHA-256 of the nonce", evidence: overNonce(hashBytes(crypto.SHA256, expected)), wantError: "nonce"},
		{name: "nonce with a trailing byte", evidence: overNonce(append(bytes.Clone(expected), 0)), wantError: "nonce"},
		{name: "no nonce", evidence: overNonce(nil), wantError: "nonce"},
	} {
		t.Run(test.name, func(t *testing.T) {
			deviceID, pcrs, _, err := verifyQuotedPCRs(test.evidence(t), expected)
			if err == nil || !strings.Contains(err.Error(), test.wantError) || deviceID != "" || len(pcrs) != 0 {
				t.Fatalf("device %q, %d PCRs, error %v; want %q and no attribution", deviceID, len(pcrs), err, test.wantError)
			}
		})
	}
}

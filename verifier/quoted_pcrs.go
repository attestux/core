package verifier

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/attestux/core/attestation"
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
)

func verifyQuotedPCRs(
	e *attestuxv1.AttestationEvidence,
	expectedNonce []byte,
) ([]attest.PCR, []*resultv1.PcrResult, error) {
	ak, err := attest.ParseAKPublic(
		e.Keys.AttestationPublic,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation public key: %w", err)
	}
	bank := sha256PCRBank(e)
	quote := attest.Quote{
		Quote:     bytes.Clone(bank.Quote.Quote),
		Signature: bytes.Clone(bank.Quote.Signature),
	}
	if err := attestation.RequireSHA256SignatureEncoding(quote.Signature); err != nil {
		return nil, nil, fmt.Errorf("verify TPM quote: %w", err)
	}

	pcrs := make([]attest.PCR, 0, len(bank.Pcrs))
	results := make([]*resultv1.PcrResult, 0, len(bank.Pcrs))
	for _, pcr := range bank.Pcrs {
		pcrs = append(pcrs, attest.PCR{
			Index:     int(pcr.Index),
			Digest:    bytes.Clone(pcr.Digest),
			DigestAlg: crypto.SHA256,
		})
		results = append(results, &resultv1.PcrResult{
			HashAlgorithm: attestation.TPMAlgSHA256,
			Pcr:           &attestuxv1.Pcr{Index: pcr.Index, Digest: bytes.Clone(pcr.Digest)},
		})
	}

	decoded, err := tpm2.DecodeAttestationData(quote.Quote)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TPM quote: %w", err)
	}
	// The library includes its nonce argument in mismatch errors. Give it only
	// the public quote nonce, then check the private challenge ourselves.
	if err := ak.Verify(quote, pcrs, decoded.ExtraData); err != nil {
		return nil, nil, fmt.Errorf("verify TPM quote: %w", err)
	}
	if subtle.ConstantTimeCompare(decoded.ExtraData, expectedNonce) != 1 {
		return nil, nil, errors.New("verify TPM quote: nonce mismatch")
	}
	// The library can accept a quote for another bank without covering any of these PCRs.
	for _, pcr := range pcrs {
		if !pcr.QuoteVerified() {
			return nil, nil, fmt.Errorf(
				"verify TPM quote: quote does not cover SHA-256 PCR %d",
				pcr.Index,
			)
		}
	}
	return pcrs, results, nil
}

func sha256PCRBank(e *attestuxv1.AttestationEvidence) *attestuxv1.PcrBankEvidence {
	for _, bank := range e.PcrBanks {
		if bank.HashAlgorithm == attestation.TPMAlgSHA256 {
			return bank
		}
	}
	return nil
}

func unsupportedPCRBankWarning(e *attestuxv1.AttestationEvidence) string {
	var ignored []uint32
	for _, bank := range e.PcrBanks {
		if bank.HashAlgorithm != attestation.TPMAlgSHA256 {
			ignored = append(ignored, bank.HashAlgorithm)
		}
	}
	if len(ignored) == 0 {
		return ""
	}
	slices.Sort(ignored)
	algorithms := make([]string, 0, len(ignored))
	for _, algorithm := range ignored {
		algorithms = append(algorithms, attestation.HashAlgorithmName(algorithm))
	}
	return fmt.Sprintf(
		"ignored unsupported PCR banks: %s; only SHA-256 was verified",
		strings.Join(algorithms, ", "),
	)
}

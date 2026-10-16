package verifier

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"strings"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
)

func verifyQuotedPCRs(
	e *attestuxv1.AttestationEvidence,
	expectedNonce []byte,
) (string, []attest.PCR, []*attestuxv1.PcrResult, error) {
	ak, canonicalAK, exactAKEncoding, err := attestation.ParseCanonicalAKPublic(
		e.AttestationPublic,
	)
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse attestation public key: %w", err)
	}
	bank := sha256PCRBank(e)
	quote := attest.Quote{
		Quote:     bytes.Clone(bank.Quote.Quote),
		Signature: bytes.Clone(bank.Quote.Signature),
	}
	if err := attestation.RequireSHA256SignatureEncoding(quote.Signature); err != nil {
		return "", nil, nil, fmt.Errorf("verify TPM quote: %w", err)
	}

	pcrs := make([]attest.PCR, 0, len(bank.Pcrs))
	results := make([]*attestuxv1.PcrResult, 0, len(bank.Pcrs))
	for _, pcr := range bank.Pcrs {
		pcrs = append(pcrs, attest.PCR{
			Index:     int(pcr.Index),
			Digest:    bytes.Clone(pcr.Digest),
			DigestAlg: crypto.SHA256,
		})
		results = append(results, &attestuxv1.PcrResult{
			HashAlgorithm: attestation.TPMAlgSHA256,
			Pcr:           &attestuxv1.Pcr{Index: pcr.Index, Digest: bytes.Clone(pcr.Digest)},
		})
	}

	if err := ak.Verify(quote, pcrs, expectedNonce); err != nil {
		return "", nil, nil, fmt.Errorf("verify TPM quote: %w", err)
	}
	// The library can accept a quote for another bank without covering any of these PCRs.
	for _, pcr := range pcrs {
		if !pcr.QuoteVerified() {
			return "", nil, nil, fmt.Errorf(
				"verify TPM quote: quote does not cover SHA-256 PCR %d",
				pcr.Index,
			)
		}
	}
	deviceID := attestation.DeriveDeviceID(canonicalAK)
	if !exactAKEncoding {
		return deviceID, nil, nil, fmt.Errorf(
			"attestation public key: %w",
			attestation.ErrNonCanonicalAKPublic,
		)
	}
	return deviceID, pcrs, results, nil
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

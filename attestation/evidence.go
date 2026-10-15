package attestation

import (
	"crypto/sha256"
	"errors"
	"fmt"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

func ValidateEvidence(e *attestuxv1.AttestationEvidence) error {
	if e == nil {
		return errors.New("missing evidence")
	}
	if len(e.AttestationPublic) == 0 || len(e.AttestationPublic) > maxAKPublicSize {
		return errors.New("invalid attestation public-key size")
	}
	if len(e.AkCreateData) == 0 || len(e.AkCreateData) > maxAKCreationSize ||
		len(e.AkCreateAttestation) == 0 ||
		len(e.AkCreateAttestation) > maxAKCreationSize ||
		len(e.AkCreateSignature) == 0 ||
		len(e.AkCreateSignature) > maxAKCreationSize {
		return errors.New("invalid attestation-key creation evidence")
	}
	if len(e.EndorsementKeys) == 0 || len(e.EndorsementKeys) > MaxEKCount {
		return fmt.Errorf(
			"invalid endorsement-key count %d",
			len(e.EndorsementKeys),
		)
	}
	if len(e.PcrBanks) == 0 || len(e.PcrBanks) > maxPCRBankCount {
		return fmt.Errorf(
			"invalid PCR bank count %d",
			len(e.PcrBanks),
		)
	}
	var bank *attestuxv1.PcrBankEvidence
	algorithms := make(map[uint32]struct{}, len(e.PcrBanks))
	for i, candidate := range e.PcrBanks {
		if err := validatePCRBank(candidate); err != nil {
			return fmt.Errorf("invalid PCR bank %d: %w", i, err)
		}
		if _, duplicate := algorithms[candidate.HashAlgorithm]; duplicate {
			return fmt.Errorf(
				"evidence contains multiple %s PCR banks",
				HashAlgorithmName(candidate.HashAlgorithm),
			)
		}
		algorithms[candidate.HashAlgorithm] = struct{}{}
		if candidate.HashAlgorithm != TPMAlgSHA256 {
			continue
		}
		bank = candidate
	}
	if bank == nil {
		return errors.New("evidence does not contain the required SHA-256 PCR bank")
	}
	if len(bank.Pcrs) != AttestedPCRCount {
		return fmt.Errorf(
			"V1 requires exactly %d SHA-256 PCRs, got %d",
			AttestedPCRCount,
			len(bank.Pcrs),
		)
	}
	for i, p := range bank.Pcrs {
		if p.Index >= AttestedPCRCount {
			return fmt.Errorf("invalid PCR %d", i)
		}
	}
	if len(e.EventLog) < minEventLogSize || len(e.EventLog) > MaxEventLogSize {
		return errors.New("invalid event-log size")
	}
	return nil
}

func validatePCRBank(bank *attestuxv1.PcrBankEvidence) error {
	if bank == nil {
		return errors.New("missing bank")
	}
	if bank.HashAlgorithm == 0 {
		return errors.New("hash algorithm is unspecified")
	}
	quote := bank.Quote
	if quote == nil ||
		len(quote.Quote) == 0 || len(quote.Quote) > maxQuoteSize ||
		len(quote.Signature) == 0 || len(quote.Signature) > maxQuoteSize {
		return errors.New("quote or signature has an invalid size")
	}
	if len(bank.Pcrs) == 0 || len(bank.Pcrs) > MaxPCRCount {
		return fmt.Errorf("PCR count %d is outside permitted range", len(bank.Pcrs))
	}
	expectedDigestSize := DigestSize(bank.HashAlgorithm)
	seen := make(map[uint32]struct{}, len(bank.Pcrs))
	for position, pcr := range bank.Pcrs {
		if pcr == nil {
			return fmt.Errorf("PCR %d is missing", position)
		}
		if pcr.Index >= MaxPCRCount {
			return fmt.Errorf("PCR index %d is outside permitted range", pcr.Index)
		}
		if _, duplicate := seen[pcr.Index]; duplicate {
			return fmt.Errorf("PCR index %d is duplicated", pcr.Index)
		}
		seen[pcr.Index] = struct{}{}
		if len(pcr.Digest) == 0 || len(pcr.Digest) > maxPCRDigestSize {
			return fmt.Errorf(
				"PCR %d digest size %d is outside permitted range",
				pcr.Index,
				len(pcr.Digest),
			)
		}
		if expectedDigestSize != 0 && len(pcr.Digest) != expectedDigestSize {
			return fmt.Errorf(
				"PCR %d digest has size %d, expected %d",
				pcr.Index,
				len(pcr.Digest),
				expectedDigestSize,
			)
		}
	}
	return nil
}

var tpmHashAlgorithms = map[uint32]struct {
	name       string
	digestSize int
}{
	TPMAlgSHA1:   {"SHA-1", 20},
	TPMAlgSHA256: {"SHA-256", sha256.Size},
	TPMAlgSHA384: {"SHA-384", 48},
	TPMAlgSHA512: {"SHA-512", 64},
}

func DigestSize(algorithm uint32) int {
	return tpmHashAlgorithms[algorithm].digestSize
}

func HashAlgorithmName(algorithm uint32) string {
	if known, ok := tpmHashAlgorithms[algorithm]; ok {
		return known.name
	}
	return fmt.Sprintf("TPM_ALG %#x", algorithm)
}

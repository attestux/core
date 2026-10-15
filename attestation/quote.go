package attestation

import (
	"fmt"
	"slices"

	"github.com/google/go-attestation/attest"
)

const maxQuoteAttempts = 3

func QuoteSHA256PCRs(
	tpm *attest.TPM,
	ak *attest.AK,
	nonce []byte,
) (*attest.Quote, []attest.PCR, error) {
	parameters := ak.AttestationParameters()
	public, err := attest.ParseAKPublic(parameters.Public)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local attestation key: %w", err)
	}
	selected := make([]int, AttestedPCRCount)
	for index := range selected {
		selected[index] = index
	}
	// IMA can extend PCR 10 between the read and quote. Retry if they disagree.
	var verifyErr error
	for range maxQuoteAttempts {
		pcrs, err := tpm.PCRs(attest.HashSHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("read SHA-256 PCRs: %w", err)
		}
		pcrs = slices.DeleteFunc(pcrs, func(pcr attest.PCR) bool {
			return pcr.Index < 0 || pcr.Index >= AttestedPCRCount
		})
		if len(pcrs) != AttestedPCRCount {
			return nil, nil, fmt.Errorf(
				"SHA-256 bank returned %d selected PCRs, expected %d",
				len(pcrs),
				AttestedPCRCount,
			)
		}
		quote, err := ak.QuotePCRs(tpm, nonce, attest.HashSHA256, selected)
		if err != nil {
			return nil, nil, fmt.Errorf("quote SHA-256 PCRs: %w", err)
		}
		if verifyErr = public.Verify(*quote, pcrs, nonce); verifyErr == nil {
			return quote, pcrs, nil
		}
	}
	return nil, nil, fmt.Errorf("verify local SHA-256 quote: %w", verifyErr)
}

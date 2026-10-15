// Package attestationtest provides shared evidence fixtures. Importing attestation
// here would create a test import cycle.
package attestationtest

import (
	"crypto/sha256"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

func MakeUnsupportedPCRBank(
	evidence *attestuxv1.AttestationEvidence,
	algorithm uint32,
	digestSize int,
) *attestuxv1.PcrBankEvidence {
	bank := proto.Clone(evidence.PcrBanks[0]).(*attestuxv1.PcrBankEvidence)
	bank.HashAlgorithm = algorithm
	for _, pcr := range bank.Pcrs {
		pcr.Digest = make([]byte, digestSize)
	}
	return bank
}

func MinimallyShapedEvidence() *attestuxv1.AttestationEvidence {
	evidence := &attestuxv1.AttestationEvidence{
		AttestationPublic:   []byte{1},
		AkCreateData:        []byte{1},
		AkCreateAttestation: []byte{1},
		AkCreateSignature:   []byte{1},
		EndorsementKeys: []*attestuxv1.EndorsementKey{{
			PublicKey:   []byte{1},
			Certificate: []byte{1},
		}},
		PcrBanks: []*attestuxv1.PcrBankEvidence{{
			HashAlgorithm: 0x000b,
			Quote: &attestuxv1.Quote{
				Quote:     []byte{1},
				Signature: []byte{2},
			},
		}},
		EventLog: make([]byte, 32),
	}
	bank := evidence.PcrBanks[0]
	for index := uint32(0); index < 16; index++ {
		bank.Pcrs = append(bank.Pcrs, &attestuxv1.Pcr{
			Index:  index,
			Digest: make([]byte, sha256.Size),
		})
	}
	return evidence
}

func FailedReport() *attestuxv1.VerificationReport {
	return &attestuxv1.VerificationReport{
		DeviceId:       "device",
		Status:         attestuxv1.VerificationStatus_VERIFICATION_STATUS_FAILED,
		EvidenceSha256: make([]byte, sha256.Size),
		TrustPolicy:    attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		Errors:         []string{"evidence rejected"},
	}
}

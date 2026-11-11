package attestation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/attestux/core/attestation/attestationtest"
	"github.com/attestux/protocol-go/attestux/v1"

	"google.golang.org/protobuf/proto"
)

func TestValidateEvidenceChecksShape(t *testing.T) {
	sha256PCRs := func(count int) []*attestuxv1.Pcr {
		pcrs := make([]*attestuxv1.Pcr, count)
		for i := range pcrs {
			pcrs[i] = &attestuxv1.Pcr{Index: uint32(i), Digest: make([]byte, 32)}
		}
		return pcrs
	}
	endorsementKeys := func(e *attestuxv1.AttestationEvidence, count int) []*attestuxv1.EndorsementKey {
		keys := make([]*attestuxv1.EndorsementKey, count)
		for i := range keys {
			keys[i] = e.Keys.EndorsementKeys[0]
		}
		return keys
	}
	for _, test := range []struct {
		name   string
		mutate func(*attestuxv1.AttestationEvidence)
		want   string
	}{
		{"missing keys", func(e *attestuxv1.AttestationEvidence) {
			e.Keys = nil
		}, "missing attestation keys"},
		{"empty attestation public", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.AttestationPublic = nil
		}, "invalid attestation public-key size"},
		{"oversized attestation public", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.AttestationPublic = make([]byte, maxAKPublicSize+1)
		}, "invalid attestation public-key size"},
		{"empty AK creation data", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.AkCreateData = nil
		}, "invalid attestation-key creation evidence"},
		{"oversized AK creation signature", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.AkCreateSignature = make([]byte, maxAKCreationSize+1)
		}, "invalid attestation-key creation evidence"},
		{"no PCR banks", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks = nil
		}, "invalid PCR bank count 0"},
		{"too many PCR banks", func(e *attestuxv1.AttestationEvidence) {
			for len(e.PcrBanks) <= maxPCRBankCount {
				e.PcrBanks = append(e.PcrBanks, e.PcrBanks[0])
			}
		}, fmt.Sprintf("invalid PCR bank count %d", maxPCRBankCount+1)},
		{"wrong digest length", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks[0].Pcrs[0].Digest = make([]byte, 31)
		}, "PCR 0 digest has size 31, expected 32"},
		{"PCR beyond V1 scope", func(e *attestuxv1.AttestationEvidence) {
			pcrs := e.PcrBanks[0].Pcrs
			pcrs[len(pcrs)-1].Index = AttestedPCRCount
		}, fmt.Sprintf("invalid PCR %d", AttestedPCRCount)},
		{"15 PCRs", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks[0].Pcrs = sha256PCRs(15)
		}, "requires exactly 16 SHA-256 PCRs"},
		{"17 PCRs", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks[0].Pcrs = sha256PCRs(17)
		}, "requires exactly 16 SHA-256 PCRs"},
		{"no endorsement keys", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.EndorsementKeys = nil
		}, "invalid endorsement-key count 0"},
		{"maximum endorsement keys", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.EndorsementKeys = endorsementKeys(e, MaxEKCount)
		}, ""},
		{"too many endorsement keys", func(e *attestuxv1.AttestationEvidence) {
			e.Keys.EndorsementKeys = endorsementKeys(e, MaxEKCount+1)
		}, fmt.Sprintf("invalid endorsement-key count %d", MaxEKCount+1)},
		{"additional unsupported bank", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks = append(e.PcrBanks, attestationtest.MakeUnsupportedPCRBank(e, 0x000d, 64))
		}, ""},
		{"duplicate SHA-256 bank", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks = append(e.PcrBanks, proto.Clone(e.PcrBanks[0]).(*attestuxv1.PcrBankEvidence))
		}, "multiple SHA-256 PCR banks"},
		{"missing SHA-256 bank", func(e *attestuxv1.AttestationEvidence) {
			e.PcrBanks[0] = attestationtest.MakeUnsupportedPCRBank(e, 0x000d, 64)
		}, "required SHA-256 PCR bank"},
		{"duplicate SHA-512 bank", func(e *attestuxv1.AttestationEvidence) {
			bank := attestationtest.MakeUnsupportedPCRBank(e, 0x000d, 64)
			e.PcrBanks = append(e.PcrBanks, bank, proto.Clone(bank).(*attestuxv1.PcrBankEvidence))
		}, "multiple SHA-512 PCR banks"},
		{"duplicate unknown bank", func(e *attestuxv1.AttestationEvidence) {
			bank := attestationtest.MakeUnsupportedPCRBank(e, 0x0042, 17)
			e.PcrBanks = append(e.PcrBanks, bank, proto.Clone(bank).(*attestuxv1.PcrBankEvidence))
		}, "multiple TPM_ALG 0x42 PCR banks"},
		{"event log below the TCG header", func(e *attestuxv1.AttestationEvidence) {
			e.EventLog = make([]byte, minEventLogSize-1)
		}, "invalid event-log size"},
		{"smallest accepted event log", func(e *attestuxv1.AttestationEvidence) {
			e.EventLog = make([]byte, minEventLogSize)
		}, ""},
		{"largest accepted event log", func(e *attestuxv1.AttestationEvidence) {
			e.EventLog = make([]byte, MaxEventLogSize)
		}, ""},
		{"event log beyond the limit", func(e *attestuxv1.AttestationEvidence) {
			e.EventLog = make([]byte, MaxEventLogSize+1)
		}, "invalid event-log size"},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := attestationtest.MinimallyShapedEvidence()
			test.mutate(e)
			err := ValidateEvidence(e)
			if test.want == "" {
				if err != nil {
					t.Fatalf("rejected valid evidence: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestValidateEvidenceChecksUnsupportedBankStructure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*attestuxv1.PcrBankEvidence)
		want   string
	}{
		{
			name: "zero algorithm",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.HashAlgorithm = 0
			},
			want: "hash algorithm is unspecified",
		},
		{
			name: "missing quote",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Quote = nil
			},
			want: "quote or signature has an invalid size",
		},
		{
			name: "oversized signature",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Quote.Signature = make([]byte, maxQuoteSize+1)
			},
			want: "quote or signature has an invalid size",
		},
		{
			name: "no PCRs",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs = nil
			},
			want: "PCR count 0 is outside permitted range",
		},
		{
			name: "too many PCRs",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs = make([]*attestuxv1.Pcr, MaxPCRCount+1)
			},
			want: fmt.Sprintf("PCR count %d is outside permitted range", MaxPCRCount+1),
		},
		{
			name: "PCR index outside range",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs[0].Index = MaxPCRCount
			},
			want: fmt.Sprintf("PCR index %d is outside permitted range", MaxPCRCount),
		},
		{
			name: "duplicate PCR index",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs[1].Index = bank.Pcrs[0].Index
			},
			want: "PCR index 0 is duplicated",
		},
		{
			name: "empty digest",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs[0].Digest = nil
			},
			want: "PCR 0 digest size 0 is outside permitted range",
		},
		{
			name: "wrong known digest size",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.Pcrs[0].Digest = make([]byte, 63)
			},
			want: "PCR 0 digest has size 63, expected 64",
		},
		{
			name: "oversized unknown digest",
			mutate: func(bank *attestuxv1.PcrBankEvidence) {
				bank.HashAlgorithm = 0x0042
				bank.Pcrs[0].Digest = make([]byte, maxPCRDigestSize+1)
			},
			want: fmt.Sprintf("PCR 0 digest size %d is outside permitted range", maxPCRDigestSize+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := attestationtest.MinimallyShapedEvidence()
			bank := attestationtest.MakeUnsupportedPCRBank(evidence, 0x000d, 64)
			test.mutate(bank)
			evidence.PcrBanks = append(evidence.PcrBanks, bank)
			err := ValidateEvidence(evidence)
			if err == nil || !strings.Contains(err.Error(), "invalid PCR bank 1: "+test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

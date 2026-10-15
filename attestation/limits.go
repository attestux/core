package attestation

import "github.com/attestux/protocol-go/frame"

const (
	MaxEvidenceSize = frame.MaxEvidencePayload
	MaxEventLogSize = 24 << 20
	// The TCG SHA-1 event header: PCR index, event type, 20-byte digest, event size.
	minEventLogSize   = 32
	maxAKPublicSize   = 64 << 10
	maxAKCreationSize = 64 << 10
	// This limit applies to the whole encoded activation message.
	MaxActivationMessageSize = frame.MaxControlPayload
	maxQuoteSize             = 64 << 10
	minNonceSize             = 16
	MaxNonceSize             = 32

	AttestedPCRCount = 16
	MaxPCRCount      = 24
	maxPCRBankCount  = 16
	maxPCRDigestSize = 64
	MaxEKCount       = 4

	// Unknown banks are reported by identifier and never replayed.
	TPMAlgSHA1   = 0x0004
	TPMAlgSHA256 = 0x000b
	TPMAlgSHA384 = 0x000c
	TPMAlgSHA512 = 0x000d
)

package verifier

const (
	MaxReportSize        = 16 << 20
	MaxReceiptSize       = 64 << 10
	maxEKPublicSize      = 4 << 10
	maxEKCertificateSize = 64 << 10
	maxEventCount        = 100_000

	// Leave room in the report. Verification still uses the full log.
	maxNormalizedEventBytes = MaxReportSize - (1 << 20)
	// Library errors can echo peer data, so limit each message. The cap also keeps
	// the receipt, which carries the errors, inside one 64 KiB control frame.
	maxDiagnosticMessageBytes = 4 << 10
)

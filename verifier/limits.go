package verifier

const (
	maxReportSize        = 16 << 20
	maxEKCertificateSize = 64 << 10
	maxEventCount        = 100_000

	// Leave room in the report. Verification still uses the full log.
	maxNormalizedEventBytes = maxReportSize - (1 << 20)
	// Library errors can echo peer data, so limit each message. The cap also keeps
	// the receipt, which carries the errors, inside one 64 KiB control frame.
	maxDiagnosticMessageBytes = 4 << 10
)

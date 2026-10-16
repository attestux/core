package verifier

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"google.golang.org/protobuf/proto"
)

func TestReplayEventLogSkipsMissingDigests(t *testing.T) {
	event := logEvent{pcrIndex: 7, eventType: 5, data: []byte("sha1 only")}
	digest := hashBytes(crypto.SHA1, event.data)
	for _, format := range []string{"crypto-agile", "legacy SHA-1"} {
		t.Run(format, func(t *testing.T) {
			var log bytes.Buffer
			if format == "crypto-agile" {
				log.Write(cryptoAgileEventLogHeader(t, []attest.HashAlg{attest.HashSHA1, attest.HashSHA256}))
			}
			writeLE(t, &log, event.pcrIndex)
			writeLE(t, &log, event.eventType)
			if format == "crypto-agile" {
				writeLE(t, &log, uint32(1))
				writeLE(t, &log, uint16(attest.HashSHA1))
			}
			log.Write(digest)
			writeLE(t, &log, uint32(len(event.data)))
			log.Write(event.data)
			results := singlePCRResult(7)
			replay := replayEventLog(log.Bytes(), quotedSHA256PCR(7, event), results, maxNormalizedEventBytes)

			if results[0].EventLogReplayed || !containsMessage(replay.warnings, "PCR 7 SHA-256 quote verified, but event-log replay failed") {
				t.Fatalf("PCR 7 replayed without a SHA-256 digest: %+v, warnings %q", results[0], replay.warnings)
			}
			if len(replay.events) != 1 || len(replay.events[0].Digests) != 1 ||
				replay.events[0].Digests[0].HashAlgorithm != attestation.TPMAlgSHA1 ||
				!bytes.Equal(replay.events[0].Digests[0].Digest, digest) ||
				replay.events[0].Digests[0].State != attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED {
				t.Fatalf("normalized digests = %+v, want the original unverified SHA-1 digest only", replay.events)
			}
		})
	}
}

func TestReplayEventLogKeepsDigestsWithTheirOwnEntry(t *testing.T) {
	sha256Only := []attest.HashAlg{attest.HashSHA256}
	bothBanks := []attest.HashAlg{attest.HashSHA1, attest.HashSHA256}
	unattested := logEvent{pcrIndex: 23, eventType: 5, data: []byte("dropped before alignment")}
	first := logEvent{pcrIndex: 7, eventType: 5, data: []byte("SHA-256 only")}
	second := logEvent{pcrIndex: 7, eventType: 5, data: []byte("both banks")}
	entry := func(banks []attest.HashAlg, event logEvent) []byte {
		return cryptoAgileEventLog(t, banks, event)[len(cryptoAgileEventLogHeader(t, banks)):]
	}
	raw := slices.Concat(
		cryptoAgileEventLogHeader(t, bothBanks),
		entry(bothBanks, unattested),
		entry(sha256Only, first),
		entry(bothBanks, second),
	)
	results := singlePCRResult(7)
	replay := replayEventLog(raw, quotedSHA256PCR(7, first, second), results, maxNormalizedEventBytes)

	if !results[0].EventLogReplayed || len(replay.events) != 2 {
		t.Fatalf("PCR 7 result = %+v with %d events, warnings %q", results[0], len(replay.events), replay.warnings)
	}
	for i, want := range []struct {
		source logEvent
		banks  []attest.HashAlg
	}{{first, sha256Only}, {second, bothBanks}} {
		digests := replay.events[i].Digests
		if len(digests) != len(want.banks) {
			t.Fatalf("event %d carries %d digests, want %d", i, len(digests), len(want.banks))
		}
		for j, bank := range want.banks {
			if digests[j].HashAlgorithm != uint32(bank) ||
				!bytes.Equal(digests[j].Digest, hashBytes(eventLogHashes[bank], want.source.data)) {
				t.Fatalf("event %d digest %d = %v, want the %v digest of its own data", i, j, digests[j], bank)
			}
		}
	}
}

func TestReplayEventLogClassifiesDigestsPerPCR(t *testing.T) {
	banks := []attest.HashAlg{attest.HashSHA1, attest.HashSHA256}
	extended := []logEvent{
		{pcrIndex: 7, eventType: 5, data: []byte("first PCR 7 measurement")},
		{pcrIndex: 7, eventType: 5, data: []byte("second PCR 7 measurement")},
	}
	unexplained := logEvent{
		pcrIndex:  8,
		eventType: 5,
		data:      []byte("PCR 8 measurement"),
	}
	raw := cryptoAgileEventLog(t, banks, append(extended, unexplained)...)
	pcrs := append(quotedSHA256PCR(7, extended...), attest.PCR{
		Index:     8,
		Digest:    bytes.Repeat([]byte{0xa5}, sha256.Size),
		DigestAlg: crypto.SHA256,
	})
	results := append(singlePCRResult(7), singlePCRResult(8)...)
	replay := replayEventLog(raw, pcrs, results, maxNormalizedEventBytes)

	if !results[0].EventLogReplayed || results[0].ReplayedEventCount != 2 {
		t.Fatalf("PCR 7 result = %+v, want 2 replayed events", results[0])
	}
	if results[1].EventLogReplayed {
		t.Fatalf("PCR 8 replayed an event log it does not match: %+v", results[1])
	}
	if len(replay.warnings) != 1 || !strings.Contains(replay.warnings[0], "PCR 8") {
		t.Fatalf("warnings = %q, want one PCR 8 replay failure", replay.warnings)
	}
	if len(replay.events) != 3 {
		t.Fatalf("normalized %d events, want 3", len(replay.events))
	}

	wantStates := []attestuxv1.VerificationState{
		attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED,
		attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED,
		attestuxv1.VerificationState_VERIFICATION_STATE_FAILED,
	}
	source := append(extended, unexplained)
	for i, event := range replay.events {
		if event.Sequence != uint32(i) ||
			event.PcrIndex != source[i].pcrIndex {
			t.Fatalf("event %d = %+v, want PCR %d", i, event, source[i].pcrIndex)
		}
		if len(event.Digests) != len(banks) {
			t.Fatalf("event %d carries %d digests, want %d", i, len(event.Digests), len(banks))
		}
		for _, digest := range event.Digests {
			want := attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED
			if digest.HashAlgorithm == attestation.TPMAlgSHA256 {
				want = wantStates[i]
			}
			if digest.State != want {
				t.Fatalf(
					"event %d %s digest state = %v, want %v",
					i,
					attestation.HashAlgorithmName(digest.HashAlgorithm),
					digest.State,
					want,
				)
			}
			if !bytes.Equal(
				digest.Digest,
				hashBytes(eventLogHashes[attest.HashAlg(digest.HashAlgorithm)], source[i].data),
			) {
				t.Fatalf("event %d %#x digest does not match the log", i, digest.HashAlgorithm)
			}
		}
	}
}

func TestReplayEventLogCoversUnextendedInitialPCR(t *testing.T) {
	banks := []attest.HashAlg{attest.HashSHA256}
	extended := logEvent{
		pcrIndex:  7,
		eventType: 5,
		data:      []byte("PCR 7 measurement"),
	}
	raw := cryptoAgileEventLog(t, banks, extended)
	pcrs := append(quotedSHA256PCR(7, extended), quotedSHA256PCR(9)...)
	results := append(singlePCRResult(7), singlePCRResult(9)...)

	if replay := replayEventLog(raw, pcrs, results, maxNormalizedEventBytes); len(replay.warnings) != 0 {
		t.Fatalf("warnings = %q, want none", replay.warnings)
	}
	if !results[1].EventLogReplayed || results[1].ReplayedEventCount != 0 {
		t.Fatalf("PCR 9 result = %+v, want replayed with no extends", results[1])
	}

	// The library accepts any PCR value with no events. We require an initial value.
	pcrs = append(pcrs[:1], quotedSHA256PCR(10, extended)...)
	results = append(singlePCRResult(7), singlePCRResult(10)...)
	replay := replayEventLog(raw, pcrs, results, maxNormalizedEventBytes)
	if results[1].EventLogReplayed ||
		!containsMessage(replay.warnings, "no extending event covers non-initial PCR 10") {
		t.Fatalf("PCR 10 result = %+v, warnings %q; want a coverage failure", results[1], replay.warnings)
	}
}

func TestReplayEventLogWarnsAboutQuirkAssistedReplay(t *testing.T) {
	logged := logEvent{
		pcrIndex:  5,
		eventType: 5,
		data:      []byte("logged PCR 5 measurement"),
	}
	assumed := []logEvent{
		{pcrIndex: 5, data: []byte("Exit Boot Services Invocation")},
		{pcrIndex: 5, data: []byte("Exit Boot Services Returned with Success")},
	}
	raw := cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, logged)
	pcrs := quotedSHA256PCR(5, append([]logEvent{logged}, assumed...)...)
	results := singlePCRResult(5)
	replay := replayEventLog(raw, pcrs, results, maxNormalizedEventBytes)

	if !results[0].EventLogReplayed {
		t.Fatalf("PCR 5 result = %+v, want the workaround to complete the replay", results[0])
	}
	if !results[0].ReplayUsedUnloggedEvents {
		t.Fatalf("PCR 5 result = %+v, want the workaround persisted in the report", results[0])
	}
	if !containsMessage(replay.warnings, "assuming 2 entries the event log does not contain") {
		t.Fatalf("warnings = %q, want the unlogged-entry disclosure", replay.warnings)
	}
	if len(replay.events) != 1 {
		t.Fatalf("normalized %d events, want only the logged one", len(replay.events))
	}
	for _, digest := range replay.events[0].Digests {
		if digest.State != attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED {
			t.Fatalf("logged event digest state = %v, want verified", digest.State)
		}
	}
}

func TestReplayEventLogDoesNotWarnWhenLogExplainsPCR(t *testing.T) {
	logged := logEvent{
		pcrIndex:  5,
		eventType: 5,
		data:      []byte("logged PCR 5 measurement"),
	}
	raw := cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, logged)
	pcrs := quotedSHA256PCR(5, logged)
	results := singlePCRResult(5)

	if replay := replayEventLog(raw, pcrs, results, maxNormalizedEventBytes); len(replay.warnings) != 0 {
		t.Fatalf("warnings = %q, want none", replay.warnings)
	}
	if results[0].ReplayUsedUnloggedEvents {
		t.Fatalf("PCR 5 result = %+v, did not use unlogged events", results[0])
	}
}

func TestReplayEventLogLimitsNormalizationWithoutSkippingReplay(t *testing.T) {
	measurement := logEvent{
		pcrIndex:  7,
		eventType: 5,
		data:      []byte("measurement retained only in raw evidence"),
	}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		measurement,
	)
	pcrs := quotedSHA256PCR(7, measurement)

	// The raw data fits the second budget, but the encoded event doesn't.
	for _, budget := range []int{1, len(measurement.data) + 1} {
		results := singlePCRResult(7)
		replay := replayEventLog(raw, pcrs, results, budget)

		if len(replay.events) != 0 {
			t.Fatalf("normalized %d events with a %d-byte budget", len(replay.events), budget)
		}
		if !results[0].EventLogReplayed || results[0].ReplayedEventCount != 1 {
			t.Fatalf("complete event log was not replayed: %+v", results[0])
		}
		if replay.omittedEventCount != 1 {
			t.Fatalf("omitted event count = %d, want 1", replay.omittedEventCount)
		}
		if !replay.incomplete {
			t.Fatal("truncated normalization was not marked incomplete")
		}
		if len(replay.warnings) != 1 ||
			!strings.Contains(replay.warnings[0], "normalized 0 of 1") ||
			!strings.Contains(replay.warnings[0], "complete log") {
			t.Fatalf("normalization warning = %q", replay.warnings)
		}
	}
}

func TestReplayEventLogProductionBudgetFitsReport(t *testing.T) {
	const eventCount = 20
	payload := bytes.Repeat([]byte{0xa5}, 1<<20)
	measurements := make([]logEvent, eventCount)
	for index := range measurements {
		measurements[index] = logEvent{
			pcrIndex:  7,
			eventType: 5,
			data:      payload,
		}
	}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		measurements...,
	)
	if len(raw) > attestation.MaxEventLogSize {
		t.Fatalf("synthetic event log is %d bytes, limit is %d", len(raw), attestation.MaxEventLogSize)
	}

	pcrs := quotedSHA256PCR(7, measurements...)
	pcrResults := attestedPCRResults()
	replay := replayEventLog(raw, pcrs, pcrResults, maxNormalizedEventBytes)

	if replay.omittedEventCount == 0 || !replay.incomplete {
		t.Fatal("production normalization budget did not truncate the large log")
	}
	if !pcrResults[7].EventLogReplayed ||
		pcrResults[7].ReplayedEventCount != eventCount {
		t.Fatalf("complete event log was not replayed: %+v", pcrResults[7])
	}
	normalized := &attestuxv1.VerificationReport{Events: replay.events}
	if size := proto.Size(normalized); size < maxNormalizedEventBytes-(2<<20) ||
		size > maxNormalizedEventBytes {
		t.Fatalf(
			"normalization retained %d bytes under a %d-byte production budget",
			size,
			maxNormalizedEventBytes,
		)
	}
	report := &attestuxv1.VerificationReport{
		DeviceId:           strings.Repeat("a", 64),
		Pcrs:               pcrResults,
		Events:             replay.events,
		Warnings:           replay.warnings,
		EvidenceSha256:     make([]byte, sha256.Size),
		TrustPolicy:        attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
		Status:             attestuxv1.VerificationStatus_VERIFICATION_STATUS_PENDING_ACTIVATION,
		EventLogIncomplete: replay.incomplete,
		OmittedEventCount:  replay.omittedEventCount,
	}
	if size := proto.Size(report); size > MaxReportSize {
		t.Fatalf("production-normalized report is %d bytes, limit is %d", size, MaxReportSize)
	}
}

func TestReplayEventLogStopsBeyondTheEventCountLimit(t *testing.T) {
	measurement := logEvent{pcrIndex: 7, eventType: 5, data: []byte("m")}
	for _, test := range []struct {
		name     string
		count    int
		replayed bool
	}{
		{"at the limit", maxEventCount, true},
		{"beyond the limit", maxEventCount + 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			measurements := make([]logEvent, test.count)
			for index := range measurements {
				measurements[index] = measurement
			}
			raw := cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, measurements...)
			results := singlePCRResult(7)
			replay := replayEventLog(raw, quotedSHA256PCR(7, measurements...), results, maxNormalizedEventBytes)

			if results[0].EventLogReplayed != test.replayed {
				t.Fatalf("PCR 7 replayed = %v, want %v", results[0].EventLogReplayed, test.replayed)
			}
			if test.replayed {
				if len(replay.events) != test.count || replay.incomplete {
					t.Fatalf("normalized %d events, incomplete=%v; want all %d", len(replay.events), replay.incomplete, test.count)
				}
				return
			}
			if len(replay.events) != 0 || !replay.incomplete ||
				replay.omittedEventCount != uint32(test.count) ||
				!containsMessage(replay.warnings, fmt.Sprintf("replay limit is %d", maxEventCount)) {
				t.Fatalf("oversized log was replayed: %d events, omitted %d, warnings %q", len(replay.events), replay.omittedEventCount, replay.warnings)
			}
		})
	}
}

func TestReplayEventLogReportsAnUnparsableLog(t *testing.T) {
	header := cryptoAgileEventLogHeader(t, []attest.HashAlg{attest.HashSHA256})
	results := singlePCRResult(7)
	replay := replayEventLog(header[:len(header)-1], quotedSHA256PCR(7), results, maxNormalizedEventBytes)

	if !replay.incomplete || len(replay.events) != 0 || results[0].EventLogReplayed ||
		len(replay.warnings) != 1 || !strings.Contains(replay.warnings[0], "event log could not be parsed") {
		t.Fatalf("truncated header: incomplete=%v, %d events, result %+v, warnings %q", replay.incomplete, len(replay.events), results[0], replay.warnings)
	}
}

func TestReplayEventLogDropsUnattestedRegistersQuietly(t *testing.T) {
	attested := logEvent{pcrIndex: 7, eventType: 5, data: []byte("attested")}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		attested,
		logEvent{pcrIndex: 23, eventType: 5, data: []byte("out of scope")},
	)
	pcrs := quotedSHA256PCR(7, attested)
	pcrResults := attestedPCRResults()
	replay := replayEventLog(raw, pcrs, pcrResults, maxNormalizedEventBytes)

	if replay.incomplete || replay.omittedEventCount != 0 {
		t.Fatalf(
			"unattested register reported as an omission: incomplete=%v omitted=%d",
			replay.incomplete,
			replay.omittedEventCount,
		)
	}
	if len(replay.warnings) != 0 {
		t.Fatalf("unattested register warned: %v", replay.warnings)
	}
	if len(replay.events) != 1 || replay.events[0].PcrIndex != 7 {
		t.Fatalf("normalized events = %+v, want only PCR 7", replay.events)
	}
}

func TestReplayEventLogReportsInvalidPCRIndices(t *testing.T) {
	attested := logEvent{pcrIndex: 7, eventType: 5, data: []byte("attested")}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		attested,
		logEvent{pcrIndex: 23, eventType: 5, data: []byte("valid but out of scope")},
		logEvent{pcrIndex: attestation.MaxPCRCount, eventType: 5, data: []byte("invalid")},
		logEvent{pcrIndex: ^uint32(0), eventType: 5, data: []byte("invalid maximum")},
	)
	pcrs := quotedSHA256PCR(7, attested)
	pcrResults := attestedPCRResults()
	replay := replayEventLog(raw, pcrs, pcrResults, maxNormalizedEventBytes)

	if !replay.incomplete || replay.omittedEventCount != 2 {
		t.Fatalf(
			"invalid registers not reported: incomplete=%v omitted=%d",
			replay.incomplete,
			replay.omittedEventCount,
		)
	}
	if len(replay.warnings) != 1 ||
		!strings.Contains(replay.warnings[0], "2 entries with an invalid PCR index") {
		t.Fatalf("invalid-register warning = %q", replay.warnings)
	}
	if len(replay.events) != 1 || replay.events[0].PcrIndex != 7 {
		t.Fatalf("normalized events = %+v, want only PCR 7", replay.events)
	}
}

func TestClassifyEventVerifiesOnlyExtendingEntries(t *testing.T) {
	extending := attest.Event{Index: 7, Type: 5, Data: []byte("boot"), Digest: []byte{0xab}}
	noAction := attest.Event{Index: 7, Type: eventTypeNoAction, Data: []byte("Spec ID Event03")}
	replay := pcrReplay{7: attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED}

	if got := replay.classifyEvent(attestation.TPMAlgSHA256, extending); got !=
		attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED {
		t.Fatalf("extending entry = %v, want verified", got)
	}
	if got := replay.classifyEvent(attestation.TPMAlgSHA256, noAction); got !=
		attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED {
		t.Fatalf("EV_NO_ACTION entry = %v, want unverified", got)
	}
}

func TestClassifyEventReportsFailedAndUnattestedRegisters(t *testing.T) {
	failedEvent := attest.Event{Index: 5, Type: 1, Digest: []byte{0x01}}
	unknownEvent := attest.Event{Index: 9, Type: 1, Digest: []byte{0x02}}
	replay := pcrReplay{5: attestuxv1.VerificationState_VERIFICATION_STATE_FAILED}

	if got := replay.classifyEvent(attestation.TPMAlgSHA256, failedEvent); got !=
		attestuxv1.VerificationState_VERIFICATION_STATE_FAILED {
		t.Fatalf("failed register = %v, want failed", got)
	}
	if got := replay.classifyEvent(attestation.TPMAlgSHA256, unknownEvent); got !=
		attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED {
		t.Fatalf("unreplayed register = %v, want unverified", got)
	}

	verified := attest.Event{Index: 7, Type: 1, Digest: []byte{0x03}}
	replay[7] = attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED
	if got := replay.classifyEvent(attestation.TPMAlgSHA384, verified); got !=
		attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED {
		t.Fatalf("SHA-384 digest = %v, want unverified", got)
	}
}

// Fuzz the parser directly so quote and EK checks cannot block the input.
func FuzzReplayEventLog(f *testing.F) {
	banks := []attest.HashAlg{attest.HashSHA1, attest.HashSHA256}
	measurement := logEvent{pcrIndex: 7, eventType: 5, data: []byte("seed measurement")}
	invalid := logEvent{pcrIndex: attestation.MaxPCRCount, eventType: 5, data: []byte("invalid index")}
	f.Add(cryptoAgileEventLog(f, banks, measurement))
	f.Add(cryptoAgileEventLog(f, banks, measurement, invalid))
	f.Add(cryptoAgileEventLogHeader(f, banks))
	f.Add([]byte{})
	pcrs := quotedSHA256PCR(7, measurement)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > attestation.MaxEventLogSize {
			t.Skip()
		}
		replay := replayEventLog(raw, pcrs, attestedPCRResults(), maxNormalizedEventBytes)
		for _, event := range replay.events {
			if event.PcrIndex >= attestation.AttestedPCRCount {
				t.Fatalf("normalized an event for unattested PCR %d", event.PcrIndex)
			}
		}
		normalized := &attestuxv1.VerificationReport{Events: replay.events}
		if size := proto.Size(normalized); size > maxNormalizedEventBytes {
			t.Fatalf("normalized %d bytes, budget is %d", size, maxNormalizedEventBytes)
		}
	})
}

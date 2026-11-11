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
	"github.com/attestux/protocol-go/attestux/result/v1"
	"github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"google.golang.org/protobuf/proto"
)

func TestReplayEventLogMissingDigests(t *testing.T) {
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
			results := sha256PCRResult(7, event)
			replay := replayEventLog(log.Bytes(), results)

			if results[0].EventLogReplayed || !containsMessage(replay.warnings, "PCR 7 SHA-256 quote verified, but event-log replay failed") {
				t.Fatalf("PCR 7 replayed without a SHA-256 digest: %+v, warnings %q", results[0], replay.warnings)
			}
			if len(replay.events) != 1 || len(replay.events[0].Digests) != 1 ||
				replay.events[0].Digests[0].HashAlgorithm != attestation.TPMAlgSHA1 ||
				!bytes.Equal(replay.events[0].Digests[0].Digest, digest) ||
				replay.events[0].Digests[0].State != resultv1.ReplayState_REPLAY_STATE_UNVERIFIED {
				t.Fatalf("normalized digests = %+v, want the original unverified SHA-1 digest only", replay.events)
			}
		})
	}
}

func TestReplayEventLogDigestAlignment(t *testing.T) {
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
	results := sha256PCRResult(7, first, second)
	replay := replayEventLog(raw, results)

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

func TestReplayEventLogPerPCR(t *testing.T) {
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

	results := append(sha256PCRResult(7, extended...), sha256PCRResult(8)...)
	results[1].Pcr.Digest = bytes.Repeat([]byte{0xa5}, sha256.Size)
	replay := replayEventLog(raw, results)
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
	wantStates := []resultv1.ReplayState{
		resultv1.ReplayState_REPLAY_STATE_VERIFIED,
		resultv1.ReplayState_REPLAY_STATE_VERIFIED,
		resultv1.ReplayState_REPLAY_STATE_FAILED,
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
			want := resultv1.ReplayState_REPLAY_STATE_UNVERIFIED
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

func TestReplayEventLogInitialPCR(t *testing.T) {
	banks := []attest.HashAlg{attest.HashSHA256}
	extended := logEvent{
		pcrIndex:  7,
		eventType: 5,
		data:      []byte("PCR 7 measurement"),
	}
	raw := cryptoAgileEventLog(t, banks, extended)
	results := append(sha256PCRResult(7, extended), sha256PCRResult(9)...)
	if replay := replayEventLog(raw, results); len(replay.warnings) != 0 {
		t.Fatalf("warnings = %q, want none", replay.warnings)
	}
	if !results[1].EventLogReplayed || results[1].ReplayedEventCount != 0 {
		t.Fatalf("PCR 9 result = %+v, want replayed with no extends", results[1])
	}

	// The library accepts any PCR value with no events. We require an initial value.
	results = append(sha256PCRResult(7, extended), sha256PCRResult(10, extended)...)
	replay := replayEventLog(raw, results)
	if results[1].EventLogReplayed ||
		!containsMessage(replay.warnings, "no extending event covers non-initial PCR 10") {
		t.Fatalf("PCR 10 result = %+v, warnings %q; want a coverage failure", results[1], replay.warnings)
	}
}

func TestReplayEventLogQuirkWarning(t *testing.T) {
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
	results := sha256PCRResult(5, append([]logEvent{logged}, assumed...)...)
	replay := replayEventLog(raw, results)

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
		if digest.State != resultv1.ReplayState_REPLAY_STATE_VERIFIED {
			t.Fatalf("logged event digest state = %v, want verified", digest.State)
		}
	}
}

func TestReplayEventLogNoWarning(t *testing.T) {
	logged := logEvent{
		pcrIndex:  5,
		eventType: 5,
		data:      []byte("logged PCR 5 measurement"),
	}
	raw := cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, logged)

	results := sha256PCRResult(5, logged)

	if replay := replayEventLog(raw, results); len(replay.warnings) != 0 {
		t.Fatalf("warnings = %q, want none", replay.warnings)
	}
	if results[0].ReplayUsedUnloggedEvents {
		t.Fatalf("PCR 5 result = %+v, did not use unlogged events", results[0])
	}
}

func TestReplayEventLogOmittedEvent(t *testing.T) {
	measurement := logEvent{
		pcrIndex:  7,
		eventType: 5,
		// Raw data fits the budget exactly; protobuf fields and metadata do not.
		data: bytes.Repeat([]byte{0xa5}, maxNormalizedEventBytes),
	}
	raw := cryptoAgileEventLog(t, []attest.HashAlg{attest.HashSHA256}, measurement)
	if len(raw) > attestation.MaxEventLogSize {
		t.Fatalf("synthetic event log is %d bytes, limit is %d", len(raw), attestation.MaxEventLogSize)
	}
	results := sha256PCRResult(7, measurement)
	replay := replayEventLog(raw, results)
	if len(replay.events) != 0 || replay.omittedEventCount != 1 || !replay.incomplete {
		t.Fatalf("normalized %d events, omitted %d, incomplete=%v; want one omitted event", len(replay.events), replay.omittedEventCount, replay.incomplete)
	}
	if !results[0].EventLogReplayed || results[0].ReplayedEventCount != 1 {
		t.Fatalf("complete event log was not replayed: %+v", results[0])
	}
	if len(replay.warnings) != 1 || !strings.Contains(replay.warnings[0], "normalized 0 of 1") ||
		!strings.Contains(replay.warnings[0], "complete log") {
		t.Fatalf("normalization warning = %q", replay.warnings)
	}
}

func TestReplayEventLogBudget(t *testing.T) {
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

	pcrResults := attestedPCRResults()
	pcrResults[7].Pcr.Digest = extendedSHA256PCR(measurements...)
	replay := replayEventLog(raw, pcrResults)
	omitted := uint32(eventCount - len(replay.events))
	if omitted == 0 || replay.omittedEventCount != omitted || !replay.incomplete {
		t.Fatalf("production normalization budget kept %d of %d events, omitted %d, incomplete=%v", len(replay.events), eventCount, replay.omittedEventCount, replay.incomplete)
	}
	if len(replay.warnings) != 1 ||
		!strings.Contains(replay.warnings[0], fmt.Sprintf("normalized %d of %d", len(replay.events), eventCount)) ||
		!strings.Contains(replay.warnings[0], "complete log") {
		t.Fatalf("normalization warning = %q", replay.warnings)
	}
	if !pcrResults[7].EventLogReplayed ||
		pcrResults[7].ReplayedEventCount != eventCount {
		t.Fatalf("complete event log was not replayed: %+v", pcrResults[7])
	}
	normalized := &resultv1.VerificationReport{Events: replay.events}
	if size := proto.Size(normalized); size < maxNormalizedEventBytes-(2<<20) ||
		size > maxNormalizedEventBytes {
		t.Fatalf(
			"normalization retained %d bytes under a %d-byte production budget",
			size,
			maxNormalizedEventBytes,
		)
	}
	report := &resultv1.VerificationReport{
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
	if size := proto.Size(report); size > maxReportSize {
		t.Fatalf("production-normalized report is %d bytes, limit is %d", size, maxReportSize)
	}
}

func TestReplayEventLogEventLimit(t *testing.T) {
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
			results := sha256PCRResult(7, measurements...)
			replay := replayEventLog(raw, results)

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

func TestReplayEventLogParseError(t *testing.T) {
	header := cryptoAgileEventLogHeader(t, []attest.HashAlg{attest.HashSHA256})
	results := sha256PCRResult(7)
	replay := replayEventLog(header[:len(header)-1], results)

	if !replay.incomplete || len(replay.events) != 0 || results[0].EventLogReplayed ||
		len(replay.warnings) != 1 || !strings.Contains(replay.warnings[0], "event log could not be parsed") {
		t.Fatalf("truncated header: incomplete=%v, %d events, result %+v, warnings %q", replay.incomplete, len(replay.events), results[0], replay.warnings)
	}
}

func TestReplayEventLogUnattestedPCRs(t *testing.T) {
	attested := logEvent{pcrIndex: 7, eventType: 5, data: []byte("attested")}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		attested,
		logEvent{pcrIndex: 23, eventType: 5, data: []byte("out of scope")},
	)
	pcrResults := attestedPCRResults()
	pcrResults[7].Pcr.Digest = extendedSHA256PCR(attested)

	replay := replayEventLog(raw, pcrResults)
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

func TestReplayEventLogInvalidPCRIndex(t *testing.T) {
	attested := logEvent{pcrIndex: 7, eventType: 5, data: []byte("attested")}
	raw := cryptoAgileEventLog(
		t,
		[]attest.HashAlg{attest.HashSHA256},
		attested,
		logEvent{pcrIndex: 23, eventType: 5, data: []byte("valid but out of scope")},
		logEvent{pcrIndex: attestation.MaxPCRCount, eventType: 5, data: []byte("invalid")},
		logEvent{pcrIndex: ^uint32(0), eventType: 5, data: []byte("invalid maximum")},
	)
	pcrResults := attestedPCRResults()
	pcrResults[7].Pcr.Digest = extendedSHA256PCR(attested)

	replay := replayEventLog(raw, pcrResults)
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

func TestClassifyEvent(t *testing.T) {
	const (
		verified   = resultv1.ReplayState_REPLAY_STATE_VERIFIED
		failed     = resultv1.ReplayState_REPLAY_STATE_FAILED
		unverified = resultv1.ReplayState_REPLAY_STATE_UNVERIFIED
	)
	for _, test := range []struct {
		name      string
		state     resultv1.ReplayState
		algorithm uint32
		index     int
		eventType attest.EventType
		want      resultv1.ReplayState
	}{
		{"verified PCR", verified, attestation.TPMAlgSHA256, 7, 5, verified},
		{"failed PCR", failed, attestation.TPMAlgSHA256, 7, 1, failed},
		{"unattested PCR", failed, attestation.TPMAlgSHA256, 9, 1, unverified},
		{"unsupported hash", verified, attestation.TPMAlgSHA384, 7, 1, unverified},
		{"EV_NO_ACTION at verified PCR", verified, attestation.TPMAlgSHA256, 7, eventTypeNoAction, unverified},
		{"EV_NO_ACTION at failed PCR", failed, attestation.TPMAlgSHA256, 7, eventTypeNoAction, unverified},
	} {
		t.Run(test.name, func(t *testing.T) {
			replay := pcrReplay{7: test.state}
			event := attest.Event{Index: test.index, Type: test.eventType, Digest: []byte{1}}
			if got := replay.classifyEvent(test.algorithm, event); got != test.want {
				t.Fatalf("classifyEvent = %v, want %v", got, test.want)
			}
		})
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
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > attestation.MaxEventLogSize {
			t.Skip()
		}
		results := attestedPCRResults()
		results[7].Pcr.Digest = extendedSHA256PCR(measurement)
		replay := replayEventLog(raw, results)
		for _, event := range replay.events {
			if event.PcrIndex >= attestation.AttestedPCRCount {
				t.Fatalf("normalized an event for unattested PCR %d", event.PcrIndex)
			}
		}
		normalized := &resultv1.VerificationReport{Events: replay.events}
		if size := proto.Size(normalized); size > maxNormalizedEventBytes {
			t.Fatalf("normalized %d bytes, budget is %d", size, maxNormalizedEventBytes)
		}
	})
}

package verifier

import (
	"bytes"
	"slices"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
	"google.golang.org/protobuf/proto"
)

type eventLogReplay struct {
	events            []*attestuxv1.Event
	warnings          []string
	incomplete        bool
	omittedEventCount uint32
}

func replayEventLog(
	raw []byte,
	pcrs []attest.PCR,
	pcrResults []*attestuxv1.PcrResult,
	normalizedBudget int,
) eventLogReplay {
	eventLog, err := attest.ParseEventLog(raw)
	if err != nil {
		return eventLogReplay{warnings: []string{diagnostic(
			"TPM quote verified, but the event log could not be parsed: %v",
			err,
		)}, incomplete: true}
	}

	var warnings []string
	warn := func(format string, args ...any) {
		warnings = append(warnings, diagnostic(format, args...))
	}
	allEvents := eventLog.Events(attest.HashSHA256)
	if len(allEvents) > maxEventCount {
		warn(
			"event log contains %d entries; replay limit is %d",
			len(allEvents),
			maxEventCount,
		)
		return eventLogReplay{
			warnings:          warnings,
			incomplete:        true,
			omittedEventCount: uint32(len(allEvents)),
		}
	}
	allEvents, invalidIndexEvents := keepAttestedPCREvents(allEvents)
	if invalidIndexEvents > 0 {
		warn(
			"event log contains %d entries with an invalid PCR index; they were dropped before replay",
			invalidIndexEvents,
		)
	}

	replay := replayAttestedPCRs(eventLog, pcrs, allEvents, pcrResults, warn)
	algorithms := alignEventsByAlgorithm(eventLog, allEvents)
	events := normalizeEventsWithinBudget(
		allEvents,
		algorithms,
		replay,
		normalizedBudget,
	)

	omitted := len(allEvents) - len(events)
	if omitted > 0 {
		warn(
			"normalized %d of %d event-log entries; omitted %d entries to stay within the phone report limit (quote and replay verification used the complete log)",
			len(events),
			len(allEvents),
			omitted,
		)
	}
	return eventLogReplay{
		events:            events,
		warnings:          warnings,
		incomplete:        omitted > 0 || invalidIndexEvents > 0,
		omittedEventCount: uint32(omitted + invalidIndexEvents),
	}
}

type pcrReplay map[int]attestuxv1.VerificationState

func replayAttestedPCRs(
	eventLog *attest.EventLog,
	pcrs []attest.PCR,
	allEvents []attest.Event,
	pcrResults []*attestuxv1.PcrResult,
	warn func(string, ...any),
) pcrReplay {
	replay := make(pcrReplay, len(pcrs))
	for _, pcr := range pcrs {
		verifiedEvents, replayErr := eventLog.Verify(
			[]attest.PCR{pcr},
		)
		if replayErr == nil {
			replayErr = requireEventLogExplainsPCR(pcr, verifiedEvents, allEvents)
		}
		if replayErr != nil {
			replay[pcr.Index] = attestuxv1.VerificationState_VERIFICATION_STATE_FAILED
			warn(
				"PCR %d SHA-256 quote verified, but event-log replay failed: %v",
				pcr.Index,
				replayErr,
			)
			continue
		}
		// A successful replay used every extending entry of the PCR, so any surplus
		// is a firmware workaround the received log does not contain.
		unlogged := len(verifiedEvents) - countExtendingEvents(allEvents, pcr.Index)
		if unlogged > 0 {
			warn(
				"PCR %d SHA-256 replay succeeded only after assuming %d entries the event log does not contain; the log alone does not explain this value",
				pcr.Index,
				unlogged,
			)
		}
		replay[pcr.Index] = attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED
		setPCRReplayed(pcrResults, pcr.Index, len(verifiedEvents), unlogged > 0)
	}
	return replay
}

func (r pcrReplay) classifyEvent(
	algorithmID uint32,
	event attest.Event,
) attestuxv1.VerificationState {
	if algorithmID != attestation.TPMAlgSHA256 {
		return attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED
	}
	switch state := r[event.Index]; state {
	case attestuxv1.VerificationState_VERIFICATION_STATE_FAILED:
		return state
	case attestuxv1.VerificationState_VERIFICATION_STATE_VERIFIED:
		if isExtendingEvent(event) {
			return state
		}
	}
	return attestuxv1.VerificationState_VERIFICATION_STATE_UNVERIFIED
}

type algorithmEvents struct {
	id     uint32
	events []attest.Event
}

// Events keeps the same raw-entry order for each algorithm, so positions line up.
func alignEventsByAlgorithm(
	eventLog *attest.EventLog,
	allEvents []attest.Event,
) []algorithmEvents {
	algorithms := append([]attest.HashAlg(nil), eventLog.Algs...)
	slices.Sort(algorithms)
	algorithms = slices.Compact(algorithms)
	aligned := make([]algorithmEvents, 0, len(algorithms))
	for _, algorithm := range algorithms {
		algorithmID := uint32(algorithm)
		if attestation.DigestSize(algorithmID) == 0 {
			continue
		}
		events := allEvents
		if algorithmID != attestation.TPMAlgSHA256 {
			events, _ = keepAttestedPCREvents(eventLog.Events(algorithm))
		}
		aligned = append(aligned, algorithmEvents{
			id:     algorithmID,
			events: events,
		})
	}
	return aligned
}

func normalizeEventsWithinBudget(
	allEvents []attest.Event,
	algorithms []algorithmEvents,
	replay pcrReplay,
	budget int,
) []*attestuxv1.Event {
	// Allow room for the parent field tag and length prefix.
	const repeatedMessageOverhead = 6
	normalized := make([]*attestuxv1.Event, 0, len(allEvents))
	size := 0
	for sequence, source := range allEvents {
		event := normalizeEvent(source, uint32(sequence))
		for _, algorithm := range algorithms {
			digested := algorithm.events[sequence]
			if len(digested.Digest) == 0 {
				continue
			}
			event.Digests = append(
				event.Digests,
				&attestuxv1.EventDigest{
					Digest:        bytes.Clone(digested.Digest),
					State:         replay.classifyEvent(algorithm.id, digested),
					HashAlgorithm: algorithm.id,
				},
			)
		}
		contribution := proto.Size(event) + repeatedMessageOverhead
		if size+contribution > budget {
			break
		}
		normalized = append(normalized, event)
		size += contribution
	}
	return normalized
}

// Zero events is only valid if the PCR hasn't left its initial value.
func setPCRReplayed(
	results []*attestuxv1.PcrResult,
	index int,
	replayedEvents int,
	usedUnloggedEvents bool,
) {
	for _, result := range results {
		if result.Pcr.Index == uint32(index) {
			result.EventLogReplayed = true
			result.ReplayedEventCount = uint32(replayedEvents)
			result.ReplayUsedUnloggedEvents = usedUnloggedEvents
			return
		}
	}
}

// Ignore PCRs 16-23. Indices outside the TPM range are malformed.
func keepAttestedPCREvents(events []attest.Event) ([]attest.Event, int) {
	invalid := 0
	for _, event := range events {
		if event.Index < 0 || event.Index >= attestation.MaxPCRCount {
			invalid++
		}
	}
	return slices.DeleteFunc(events, func(event attest.Event) bool {
		return event.Index < 0 || event.Index >= attestation.AttestedPCRCount
	}), invalid
}

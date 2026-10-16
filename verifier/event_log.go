package verifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

	"github.com/google/go-attestation/attest"
)

// go-attestation's replay passes a PCR the log never extends, whatever its value.
func requireEventLogExplainsPCR(pcr attest.PCR, verifiedEvents, allEvents []attest.Event) error {
	if len(verifiedEvents) > 0 || isInitialPCRValue(pcr, allEvents) {
		return nil
	}
	return fmt.Errorf("no extending event covers non-initial PCR %d", pcr.Index)
}

func isInitialPCRValue(pcr attest.PCR, events []attest.Event) bool {
	if isAllZero(pcr.Digest) {
		return true
	}

	// Startup locality sets the last byte of PCR 0 without extending it.
	if pcr.Index == 0 {
		for _, event := range events {
			if event.Index != 0 ||
				uint32(event.Type) != eventTypeNoAction ||
				len(event.Data) != 17 ||
				!bytes.HasPrefix(event.Data, []byte("StartupLocality")) {
				continue
			}
			initial := make([]byte, len(pcr.Digest))
			initial[len(initial)-1] = event.Data[len(event.Data)-1]
			if bytes.Equal(pcr.Digest, initial) {
				return true
			}
		}
	}
	return false
}

func isAllZero(value []byte) bool {
	for _, got := range value {
		if got != 0 {
			return false
		}
	}
	return len(value) > 0
}

// EV_NO_ACTION entries are informational and never extend a PCR.
const eventTypeNoAction = 3

func isExtendingEvent(event attest.Event) bool {
	return uint32(event.Type) != eventTypeNoAction
}

func countExtendingEvents(events []attest.Event, index int) int {
	count := 0
	for _, event := range events {
		if event.Index == index && isExtendingEvent(event) {
			count++
		}
	}
	return count
}

func normalizeEvent(e attest.Event, sequence uint32) *attestuxv1.Event {
	return &attestuxv1.Event{
		Sequence:      sequence,
		PcrIndex:      uint32(e.Index),
		EventType:     uint32(e.Type),
		EventTypeName: e.Type.String(),
		Data:          bytes.Clone(e.Data),
		Decoded:       formatEventData(e.Data),
	}
}

func formatEventData(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	const displayLimit = 256
	if utf8.Valid(data) {
		text := strings.TrimRight(string(data), "\x00")
		if text != "" {
			// Don't let event text add fake lines to the report.
			printable := true
			for _, r := range text {
				if !unicode.IsPrint(r) {
					printable = false
					break
				}
			}
			if printable {
				return truncateText(text, displayLimit)
			}
		}
	}
	if len(data) > displayLimit {
		return hex.EncodeToString(data[:displayLimit]) + "..."
	}
	return hex.EncodeToString(data)
}

func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

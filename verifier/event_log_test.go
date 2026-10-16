package verifier

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-attestation/attest"
)

func TestRequireEventLogExplainsPCR(t *testing.T) {
	locality := make([]byte, 32)
	locality[len(locality)-1] = 3
	extended := attest.PCR{Index: 7, Digest: bytes.Repeat([]byte{0x42}, 32)}
	for _, test := range []struct {
		name           string
		pcr            attest.PCR
		verifiedEvents []attest.Event
		allEvents      []attest.Event
		covered        bool
	}{
		{
			name:    "zero initial value",
			pcr:     attest.PCR{Index: 0, Digest: make([]byte, 32)},
			covered: true,
		},
		{
			name: "startup-locality initial value",
			pcr:  attest.PCR{Index: 0, Digest: locality},
			allEvents: []attest.Event{{
				Index: 0,
				Type:  3,
				Data:  []byte("StartupLocality\x00\x03"),
			}},
			covered: true,
		},
		{
			name: "extended without an extending event",
			pcr:  extended,
		},
		{
			name: "locality-shaped value with an unrelated PCR 0 event",
			pcr:  attest.PCR{Index: 0, Digest: locality},
			allEvents: []attest.Event{{
				Index: 0,
				Type:  5,
				Data:  []byte("NotTheLocality\x00\x00\x03"),
			}},
		},
		{
			name:           "extended with an extending event",
			pcr:            extended,
			verifiedEvents: []attest.Event{{Index: 7}},
			covered:        true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireEventLogExplainsPCR(test.pcr, test.verifiedEvents, test.allEvents)
			if (err == nil) != test.covered {
				t.Fatalf("requireEventLogExplainsPCR = %v, want covered %v", err, test.covered)
			}
		})
	}
}

func TestFormatEventDataBoundsBothBranches(t *testing.T) {
	const limit = 256
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"printable text", []byte(strings.Repeat("a", 4096))},
		{"binary", make([]byte, 4096)},
		// 256 is not a multiple of 3, so the cut lands inside a rune.
		{"multi-byte text", []byte(strings.Repeat("\u20ac", 4096))},
	} {
		t.Run(test.name, func(t *testing.T) {
			formatted := formatEventData(test.data)
			if len(formatted) > 2*limit+3 {
				t.Fatalf("formatted length %d is unbounded", len(formatted))
			}
			if !utf8.ValidString(formatted) {
				t.Fatal("formatted rendering is not valid UTF-8")
			}
		})
	}
}

func TestFormatEventDataRendersShortPayloads(t *testing.T) {
	for _, test := range []struct{ data, want string }{
		{"Boot Guard", "Boot Guard"},
		{"", ""},
		{"\x00\x01", "0001"},
		{"\xff\xfe", "fffe"},
		{"ok\x1b[2J", "6f6b1b5b324a"},
		{"grub cmd", "grub cmd"},
		{"a\nb", "610a62"},
		{"a\tb", "610962"},
		{"a\u2028b", "61e280a862"},
	} {
		if got := formatEventData([]byte(test.data)); got != test.want {
			t.Fatalf("formatEventData(%q) = %q, want %q", test.data, got, test.want)
		}
	}
}

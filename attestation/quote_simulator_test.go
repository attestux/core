//go:build tpmsimulator && cgo

package attestation

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/attestux/core/attestation/attestationtest"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestSimulatedTPMQuoteWithPCRExtensionDuringCollection(t *testing.T) {
	for _, test := range []struct {
		name                   string
		extensions, wantQuotes int
		wantError              bool
	}{
		{"one extension", 1, 2, false},
		{"extended every quote", 1 << 10, 3, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			extended, quotes := 0, 0
			_, tpm := attestationtest.NewCommandChannel(t, func(sim *simulator.Simulator, code tpmutil.Command) error {
				if code != tpm2.CmdQuote {
					return nil
				}
				quotes++
				if extended == test.extensions {
					return nil
				}
				extended++
				return tpm2.PCRExtend(sim, 10, tpm2.AlgSHA256, bytes.Repeat([]byte{0xaa}, sha256.Size), "")
			})
			ak, err := tpm.NewAK(nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ak.Close(tpm)

			quote, pcrs, err := QuoteSHA256PCRs(tpm, ak, bytes.Repeat([]byte{7}, 20))
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "verify local SHA-256 quote: quote digest didn't match pcrs provided") {
					t.Fatalf("expected quote verification failure, got %v", err)
				}
				if quote != nil || pcrs != nil {
					t.Fatal("returned quote or PCRs after verification failed")
				}
			} else {
				if err != nil {
					t.Fatalf("a PCR extension between read and quote aborted the session: %v", err)
				}
				if quote == nil || len(pcrs) != AttestedPCRCount {
					t.Fatalf("quote = %v, %d PCRs", quote, len(pcrs))
				}
			}
			if quotes != test.wantQuotes {
				t.Fatalf("quoted %d times, want %d", quotes, test.wantQuotes)
			}
		})
	}
}

//go:build attestux_simulator

package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/attestux/core/verifier/testtrust"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

func TestRuntimeVerificationPoliciesAddTheSimulatorRoot(t *testing.T) {
	block, rest := pem.Decode(testtrust.RootPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("invalid simulator root PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if got, want := hex.EncodeToString(sum[:]),
		"19b6970e3bb8777ae4b5571ec4b56de65b302e3387ebd943c308bf4a5f462880"; got != want {
		t.Fatalf("simulator root fingerprint = %s, want %s", got, want)
	}
	policies := runtimeVerificationPolicies()
	if len(policies) != 2 {
		t.Fatalf("runtime policy count = %d, want Nuvoton and simulator", len(policies))
	}
	if policies[1].id !=
		attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR ||
		policies[1].trust.roots == nil {
		t.Fatalf("unexpected simulator policy: %+v", policies[1])
	}
}

//go:build !attestux_simulator

package verifier

import "testing"

func TestRuntimeVerificationPoliciesDefault(t *testing.T) {
	if policies := runtimeVerificationPolicies(); len(policies) != 1 {
		t.Fatalf("runtime policy count = %d, want only Nuvoton", len(policies))
	}
}

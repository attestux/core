//go:build !attestux_simulator

package verifier

func runtimeVerificationPolicies() []verificationPolicy {
	return []verificationPolicy{nuvotonPolicy}
}

//go:build !attestux_simulator

package verifier

func runtimeVerificationPolicies() []verificationPolicy {
	// TODO: add Infineon and STMicro roots
	return []verificationPolicy{nuvotonPolicy}
}

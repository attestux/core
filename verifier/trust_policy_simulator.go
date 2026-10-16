//go:build attestux_simulator

package verifier

import (
	"github.com/attestux/core/verifier/testtrust"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

var simulatorTrust = certificateTrust{
	roots: mustCertPool(
		"AttesTux simulator",
		testtrust.RootPEM,
	),
}

var simulatorPolicy = verificationPolicy{
	id:         attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR,
	limitation: SimulatorLimitation,
	trust:      simulatorTrust,
}

func runtimeVerificationPolicies() []verificationPolicy {
	return []verificationPolicy{nuvotonPolicy, simulatorPolicy}
}

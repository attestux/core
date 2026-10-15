package attestation

import attestuxv1 "github.com/attestux/protocol-go/attestux/v1"

// TrustPolicyName is for display. The boolean only says the value is a known policy;
// trust comes from the roots an operator configures for it.
func TrustPolicyName(policy attestuxv1.TrustPolicy) (string, bool) {
	switch policy {
	case attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON:
		return "Nuvoton", true
	case attestuxv1.TrustPolicy_TRUST_POLICY_ATTESTUX_SIMULATOR:
		return "AttesTux simulator", true
	default:
		return policy.String(), false
	}
}

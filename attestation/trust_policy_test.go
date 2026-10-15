package attestation

import (
	"testing"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

func TestTrustPolicyNameRecognizesEveryDefinedPolicy(t *testing.T) {
	for value, name := range attestuxv1.TrustPolicy_name {
		policy := attestuxv1.TrustPolicy(value)
		_, recognized := TrustPolicyName(policy)
		if want := policy != attestuxv1.TrustPolicy_TRUST_POLICY_UNSPECIFIED; recognized != want {
			t.Errorf("%s: recognized = %v, want %v", name, recognized, want)
		}
	}
	if _, recognized := TrustPolicyName(attestuxv1.TrustPolicy(1 << 20)); recognized {
		t.Error("an undefined policy value was recognized")
	}
}

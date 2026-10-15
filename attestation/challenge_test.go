package attestation

import "testing"

func TestValidateChallengeNonceBounds(t *testing.T) {
	for size, accepted := range map[int]bool{15: false, 16: true, 32: true, 33: false} {
		if err := ValidateChallengeNonce(make([]byte, size)); (err == nil) != accepted {
			t.Errorf("nonce of %d bytes: error = %v, want accepted %v", size, err, accepted)
		}
	}
	if err := ValidateChallengeNonce(NewChallenge().Nonce); err != nil {
		t.Fatalf("issued nonce is unusable: %v", err)
	}
}

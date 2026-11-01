package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncodeAndHashEndorsementPublicPinsTheWireFingerprint(t *testing.T) {
	const point = "04" +
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	raw, err := hex.DecodeString(point)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, fingerprint, err := EncodeAndHashEndorsementPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed SubjectPublicKeyInfo for the P-256 generator and SHA-256 of those bytes.
	const wantEncoding = "3059301306072a8648ce3d020106082a8648ce3d030107034200" + point
	const wantFingerprint = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
	if got := hex.EncodeToString(encoded); got != wantEncoding {
		t.Fatalf("encoding = %s, want %s", got, wantEncoding)
	}
	if got := hex.EncodeToString(fingerprint[:]); got != wantFingerprint {
		t.Fatalf("fingerprint = %s, want %s", got, wantFingerprint)
	}
}

func TestEncodeAndHashEndorsementPublicRejectsAnUnsupportedKey(t *testing.T) {
	encoded, fingerprint, err := EncodeAndHashEndorsementPublic(nil)
	if encoded != nil || fingerprint != ([sha256.Size]byte{}) || err == nil || !strings.Contains(err.Error(), "encode endorsement public key") {
		t.Fatalf("EncodeAndHashEndorsementPublic = %x, %x, %v; want no encoding or fingerprint and an error", encoded, fingerprint, err)
	}
}

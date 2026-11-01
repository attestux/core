package attestation

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestKeyDiscoveryRequestsTheCurrentProtocol(t *testing.T) {
	request := NewChallenge()
	if request.ProtocolVersion != ProtocolVersion || len(request.ProtoReflect().GetUnknown()) != 0 {
		t.Fatal("key discovery contains unexpected fields")
	}
	raw, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x08, 1}) {
		t.Fatalf("challenge encoding = %x, want field 1 with protocol version 1", raw)
	}
}

func TestActivationQuoteNonceHashesTheSecret(t *testing.T) {
	secret := []byte("activation secret")
	want := sha256.Sum256(secret)
	got := ActivationQuoteNonce(secret)
	if !bytes.Equal(got, want[:]) || bytes.Equal(got, secret) {
		t.Fatalf("quote nonce = %x, want SHA-256(secret)", got)
	}
}

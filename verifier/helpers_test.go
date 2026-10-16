package verifier

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509/pkix"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/attestux/core/attestation"
	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
	"google.golang.org/protobuf/proto"

	"github.com/google/go-attestation/attest"
	attestationx509 "github.com/google/go-attestation/x509"
)

func marshalEvidence(t testing.TB, evidence *attestuxv1.AttestationEvidence) []byte {
	t.Helper()
	raw, err := proto.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Every completion path must forget the activation, refuse a second answer
// for that reason alone, and leave the final report as it is.
func requireActivationFinished(t testing.TB, session *VerificationSession, secret []byte) {
	t.Helper()
	if session.ActivationChallenge() != nil || session.expectedSecret != nil {
		t.Fatal("activation state survived completion")
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("secret bytes survived completion")
	}
	final := session.Report()
	for name, retry := range map[string]func() (*attestuxv1.VerificationReport, error){
		"rejection": session.RejectActivation,
		"completion": func() (*attestuxv1.VerificationReport, error) {
			return session.finishActivation(nil, "")
		},
		"completion bytes": func() (*attestuxv1.VerificationReport, error) {
			return session.CompleteActivationBytes(nil)
		},
	} {
		if _, err := retry(); err == nil || !strings.Contains(err.Error(), "no pending activation") {
			t.Fatalf("%s on a finished session returned %v, want a no-pending-activation error", name, err)
		}
	}
	if !proto.Equal(final, session.Report()) {
		t.Fatal("refused retries changed the final report")
	}
}

func containsMessage(messages []string, fragment string) bool {
	for _, message := range messages {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

func marshalTCGSubjectAltName(
	t testing.TB,
	directoryNames ...[]pkix.AttributeTypeAndValue,
) pkix.Extension {
	t.Helper()
	names := make([]pkix.Name, 0, len(directoryNames))
	for _, attributes := range directoryNames {
		names = append(names, pkix.Name{ExtraNames: attributes})
	}
	extension, err := attestationx509.MarshalSubjectAltName(
		&attestationx509.SubjectAltName{DirectoryNames: names},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return extension
}

type logEvent struct {
	pcrIndex  uint32
	eventType uint32
	data      []byte
}

func cryptoAgileEventLog(
	t testing.TB,
	banks []attest.HashAlg,
	events ...logEvent,
) []byte {
	t.Helper()
	log := bytes.NewBuffer(cryptoAgileEventLogHeader(t, banks))
	for _, event := range events {
		writeLE(t, log, event.pcrIndex)
		writeLE(t, log, event.eventType)
		writeLE(t, log, uint32(len(banks)))
		for _, bank := range banks {
			writeLE(t, log, uint16(bank))
			log.Write(hashBytes(eventLogHashes[bank], event.data))
		}
		writeLE(t, log, uint32(len(event.data)))
		log.Write(event.data)
	}
	return log.Bytes()
}

func cryptoAgileEventLogHeader(t testing.TB, banks []attest.HashAlg) []byte {
	t.Helper()
	var spec bytes.Buffer
	spec.Write([]byte("Spec ID Event03\x00"))
	writeLE(t, &spec, uint32(0))
	spec.Write([]byte{0, 2, 0, 2})
	writeLE(t, &spec, uint32(len(banks)))
	for _, bank := range banks {
		writeLE(t, &spec, uint16(bank))
		writeLE(t, &spec, uint16(eventLogHashes[bank].Size()))
	}
	spec.WriteByte(0)

	var log bytes.Buffer
	writeLE(t, &log, uint32(0))
	writeLE(t, &log, uint32(3))
	log.Write(make([]byte, 20))
	writeLE(t, &log, uint32(spec.Len()))
	log.Write(spec.Bytes())
	return log.Bytes()
}

func quotedSHA256PCR(index int, events ...logEvent) []attest.PCR {
	return []attest.PCR{{
		Index:     index,
		Digest:    extendedSHA256PCR(events...),
		DigestAlg: crypto.SHA256,
	}}
}

func singlePCRResult(index uint32) []*attestuxv1.PcrResult {
	return []*attestuxv1.PcrResult{{
		HashAlgorithm: attestation.TPMAlgSHA256,
		Pcr:           &attestuxv1.Pcr{Index: index},
	}}
}

func attestedPCRResults() []*attestuxv1.PcrResult {
	results := make([]*attestuxv1.PcrResult, 0, attestation.AttestedPCRCount)
	for index := uint32(0); index < attestation.AttestedPCRCount; index++ {
		results = append(results, &attestuxv1.PcrResult{
			HashAlgorithm: attestation.TPMAlgSHA256,
			Pcr: &attestuxv1.Pcr{
				Index:  index,
				Digest: make([]byte, sha256.Size),
			},
		})
	}
	return results
}

func extendedSHA256PCR(events ...logEvent) []byte {
	value := make([]byte, sha256.Size)
	for _, event := range events {
		digest := sha256.Sum256(event.data)
		next := sha256.Sum256(append(bytes.Clone(value), digest[:]...))
		value = next[:]
	}
	return value
}

var eventLogHashes = map[attest.HashAlg]crypto.Hash{
	attest.HashSHA1:   crypto.SHA1,
	attest.HashSHA256: crypto.SHA256,
	attest.HashSHA384: crypto.SHA384,
	attest.HashSHA512: crypto.SHA512,
}

func hashBytes(hash crypto.Hash, data []byte) []byte {
	h := hash.New()
	h.Write(data)
	return h.Sum(nil)
}

func writeLE(t testing.TB, out *bytes.Buffer, value any) {
	t.Helper()
	if err := binary.Write(out, binary.LittleEndian, value); err != nil {
		t.Fatal(err)
	}
}

func describesTrust(report *attestuxv1.VerificationReport) bool {
	return report.TrustPolicy != attestuxv1.TrustPolicy_TRUST_POLICY_UNSPECIFIED ||
		len(report.EndorsementKeySha256) != 0 ||
		containsMessage(report.Limitations, "policy limitation")
}

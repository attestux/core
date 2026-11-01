package attestation

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func encodePublic(t *testing.T, public legacytpm2.Public) []byte {
	t.Helper()
	raw, err := public.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDeviceIDAcceptsOnlyCanonicalSHA256Signers(t *testing.T) {
	generator := elliptic.P256().Params()
	signer := func(change func(*legacytpm2.Public)) []byte {
		public := legacytpm2.Public{
			Type:       legacytpm2.AlgECC,
			NameAlg:    legacytpm2.AlgSHA256,
			Attributes: legacytpm2.FlagSignerDefault,
			ECCParameters: &legacytpm2.ECCParams{
				Sign:    &legacytpm2.SigScheme{Alg: legacytpm2.AlgECDSA, Hash: legacytpm2.AlgSHA256},
				CurveID: legacytpm2.CurveNISTP256,
				Point: legacytpm2.ECPoint{
					XRaw: generator.Gx.FillBytes(make([]byte, 32)),
					YRaw: generator.Gy.FillBytes(make([]byte, 32)),
				},
			},
		}
		if change != nil {
			change(&public)
		}
		return encodePublic(t, public)
	}
	valid := signer(nil)
	wantID := fmt.Sprintf("%x", sha256.Sum256(valid))
	for _, test := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"ECDSA P-256 signer", valid, ""},
		{"trailing data", append(bytes.Clone(valid), 0), ErrNonCanonicalAKPublic.Error()},
		{"SHA-1 name", signer(func(p *legacytpm2.Public) { p.NameAlg = legacytpm2.AlgSHA1 }), "TPM Name uses SHA-1"},
		{"SHA-1 signatures", signer(func(p *legacytpm2.Public) { p.ECCParameters.Sign.Hash = legacytpm2.AlgSHA1 }), "signatures use SHA-1"},
		{"decryption key", signer(func(p *legacytpm2.Public) { p.ECCParameters.Sign = nil }), "missing ecc signature scheme"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, err := DeviceID(test.raw)
			if test.want != "" {
				if id != "" || err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("DeviceID = %q, %v; want no identity and error %q", id, err, test.want)
				}
				if test.want == ErrNonCanonicalAKPublic.Error() && !errors.Is(err, ErrNonCanonicalAKPublic) {
					t.Fatalf("error = %v, want ErrNonCanonicalAKPublic", err)
				}
				return
			}
			if err != nil || id != wantID {
				t.Fatalf("DeviceID = %q, %v; want %q", id, err, wantID)
			}
		})
	}
}

func TestSHA256SignatureEncoding(t *testing.T) {
	for _, algorithm := range []legacytpm2.Algorithm{legacytpm2.AlgRSASSA, legacytpm2.AlgRSAPSS, legacytpm2.AlgECDSA} {
		for _, hash := range []legacytpm2.Algorithm{legacytpm2.AlgSHA1, legacytpm2.AlgSHA256, legacytpm2.AlgSHA384} {
			t.Run(algorithm.String()+"/"+hash.String(), func(t *testing.T) {
				fields := []any{algorithm, hash, tpmutil.U16Bytes{1}}
				if algorithm == legacytpm2.AlgECDSA {
					fields = append(fields, tpmutil.U16Bytes{2})
				}
				raw, err := tpmutil.Pack(fields...)
				if err != nil {
					t.Fatal(err)
				}
				err = RequireSHA256SignatureEncoding(raw)
				if hash == legacytpm2.AlgSHA256 {
					if err != nil {
						t.Fatal(err)
					}
					if err := RequireSHA256SignatureEncoding(append(raw, 0)); err == nil || !strings.Contains(err.Error(), "trailing data") {
						t.Fatalf("trailing signature: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "SHA-256 is required") {
					t.Fatalf("non-SHA256 signature: %v", err)
				}
				if err := RequireSHA256SignatureEncoding(raw[:len(raw)-1]); err == nil {
					t.Fatal("accepted truncated signature")
				}
			})
		}
	}
}

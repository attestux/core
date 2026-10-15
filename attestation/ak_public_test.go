package attestation

import (
	"bytes"
	"crypto/elliptic"
	"errors"
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

func TestParseCanonicalAKPublicAcceptsOnlySHA256Signers(t *testing.T) {
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
	for _, test := range []struct {
		name  string
		raw   []byte
		exact bool
		want  string
	}{
		{"ECDSA P-256 signer", valid, true, ""},
		{"trailing data", append(bytes.Clone(valid), 0), false, ""},
		{"SHA-1 name", signer(func(p *legacytpm2.Public) { p.NameAlg = legacytpm2.AlgSHA1 }), false, "TPM Name uses SHA-1"},
		{"SHA-1 signatures", signer(func(p *legacytpm2.Public) { p.ECCParameters.Sign.Hash = legacytpm2.AlgSHA1 }), false, "signatures use SHA-1"},
		{"decryption key", signer(func(p *legacytpm2.Public) { p.ECCParameters.Sign = nil }), false, "missing ecc signature scheme"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ak, canonical, exact, err := ParseCanonicalAKPublic(test.raw)
			_, idErr := DeviceID(test.raw)
			if test.want != "" {
				if ak != nil || err == nil || !strings.Contains(err.Error(), test.want) || idErr == nil {
					t.Fatalf("parse = %v, %v; device ID error = %v; want %q", ak, err, idErr, test.want)
				}
				return
			}
			if err != nil || ak == nil || exact != test.exact || !bytes.Equal(canonical, valid) {
				t.Fatalf("parse = %v, exact %v, %v; want exact %v", ak, exact, err, test.exact)
			}
			if (test.exact && idErr != nil) || (!test.exact && !errors.Is(idErr, ErrNonCanonicalAKPublic)) {
				t.Fatalf("device ID error = %v for exact %v", idErr, test.exact)
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

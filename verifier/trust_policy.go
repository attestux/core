package verifier

import (
	"crypto/x509"
	_ "embed"
	"fmt"

	attestuxv1 "github.com/attestux/protocol-go/attestux/v1"
)

const SimulatorLimitation = "Development test only: the EK certificate chains to the public AttesTux simulator test CA and does not prove genuine TPM hardware."

//go:embed trust/nuvoton-tpm2-roots.pem
var nuvotonRootPEM []byte

//go:embed trust/nuvoton-tpm2-intermediates.pem
var nuvotonIntermediatePEM []byte

var nuvotonTrust = certificateTrust{
	roots:         mustCertPool("bundled Nuvoton roots", nuvotonRootPEM),
	intermediates: mustCertPool("bundled Nuvoton intermediates", nuvotonIntermediatePEM),
}

var nuvotonPolicy = verificationPolicy{
	id: attestuxv1.TrustPolicy_TRUST_POLICY_NUVOTON,
	limitation: "Certificate revocation status was not checked because no " +
		"current Nuvoton CRL is bundled; a revoked EK certificate may still be accepted.",
	trust: nuvotonTrust,
}

func mustCertPool(name string, certificatesPEM []byte) *x509.CertPool {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatesPEM) {
		panic(fmt.Sprintf("%s trust store is invalid", name))
	}
	return roots
}

// Package testtrust holds public test credentials for simulator builds and tests.
package testtrust

import _ "embed"

//go:embed simulator-root.pem
var RootPEM []byte

//go:embed simulator-root-key.pem
var RootKeyPEM []byte

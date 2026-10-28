module github.com/attestux/core

go 1.27.3

require (
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mobile v0.0.0-20260816165457-f98cc9b3c733 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261009151841-97e8ea77aa2a // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.7.0 // indirect
	honnef.co/go/tools v0.8.2 // indirect
)

require (
	github.com/attestux/protocol-go v0.0.0-20261008132746-b68f016b16e1
	github.com/google/go-attestation v0.6.4
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.9
	google.golang.org/protobuf v1.36.12
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
	golang.org/x/vuln/cmd/govulncheck
	honnef.co/go/tools/cmd/staticcheck
)

//go:build tpmsimulator && cgo

package attestationtest

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
)

// CommandChannel runs its callback before each simulator command.
type CommandChannel struct {
	*simulator.Simulator
	before func(sim *simulator.Simulator, code tpmutil.Command) error
	Closed bool
}

func (c *CommandChannel) Write(command []byte) (int, error) {
	if c.before != nil && len(command) >= 10 {
		code := tpmutil.Command(binary.BigEndian.Uint32(command[6:10]))
		if err := c.before(c.Simulator, code); err != nil {
			return 0, err
		}
	}
	return c.Simulator.Write(command)
}

func (c *CommandChannel) Close() error {
	c.Closed = true
	return c.Simulator.Close()
}

func NewCommandChannel(
	t testing.TB,
	before func(sim *simulator.Simulator, code tpmutil.Command) error,
) (*CommandChannel, *attest.TPM) {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sim.Close() })
	channel := &CommandChannel{Simulator: sim, before: before}
	return channel, attest.InjectSimulatedTPMForTest(channel)
}

func NewSimulatedTPM(t testing.TB) (*simulator.Simulator, *attest.TPM) {
	t.Helper()
	channel, tpm := NewCommandChannel(t, nil)
	return channel.Simulator, tpm
}

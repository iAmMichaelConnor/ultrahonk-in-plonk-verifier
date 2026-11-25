package ultrahonk

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/poseidon2"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

// parseField rejects values outside Fr rather than silently reducing them.
func parseField(s string) (*big.Int, error) {
	base := 10
	raw := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		raw = s[2:]
	}
	if raw == "" {
		return nil, fmt.Errorf("empty field")
	}
	for _, r := range raw {
		if !(r >= '0' && r <= '9') && !(base == 16 && ((r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))) {
			return nil, fmt.Errorf("invalid field %q", s)
		}
	}
	n, ok := new(big.Int).SetString(raw, base)
	if !ok || n.Cmp(protocol.ScalarModulus()) >= 0 {
		return nil, fmt.Errorf("noncanonical field %q", s)
	}
	return n, nil
}

// Option selects a compile-time verifier profile.
type Option func(*Circuit)

// WithZeroAccumulator requires all eight accumulator fields to be zero.
func WithZeroAccumulator() Option { return func(c *Circuit) { c.ZeroAccumulator = true } }

// WithPublicInputHash exposes one Poseidon2 digest instead of application inputs.
func WithPublicInputHash() Option { return func(c *Circuit) { c.HashPublicInputs = true } }

// WithDeferredPairing exposes two G1 points as eight canonical 136/118-bit
// coordinate limbs. The outer proof alone is incomplete: its verifier must
// also check e(P0, G2) * e(P1, [tau]G2) = 1 with the fixed Aztec SRS points.
func WithDeferredPairing() Option { return func(c *Circuit) { c.DeferPairing = true } }

func parseVK(vk []string) ([]frontend.Variable, [3]int, error) {
	var dims [3]int
	if len(vk) != protocol.VKFields {
		return nil, dims, fmt.Errorf("expected %d VK fields", protocol.VKFields)
	}
	values := make([]frontend.Variable, len(vk))
	for i, s := range vk {
		n, err := parseField(s)
		if err != nil {
			return nil, dims, fmt.Errorf("VK field %d: %w", i, err)
		}
		values[i] = n
	}
	for i := range dims {
		n := values[i].(*big.Int)
		if !n.IsInt64() {
			return nil, dims, fmt.Errorf("invalid VK dimensions")
		}
		if n.Int64() > int64(protocol.MaxPublicInputs) {
			return nil, dims, fmt.Errorf("unsupported VK dimensions")
		}
		dims[i] = int(n.Int64())
	}
	if dims[0] < 3 || dims[0] > protocol.Rounds || dims[1] < protocol.AccumulatorFields || dims[2] != protocol.PublicOffset {
		return nil, dims, fmt.Errorf("unsupported VK dimensions")
	}
	return values, dims, nil
}

// NewCircuit creates a shape for one authenticated VK. The hash of this fixed
// VK is computed in the circuit. Application inputs exclude the accumulator.
func NewCircuit(vk []string, zk bool, opts ...Option) (*Circuit, error) {
	c := &Circuit{VK: append([]string(nil), vk...), ZK: zk}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("nil circuit option")
		}
		opt(c)
	}
	_, dims, err := parseVK(c.VK)
	if err != nil {
		return nil, err
	}
	n := dims[1] - protocol.AccumulatorFields
	c.Proof = make([]frontend.Variable, protocol.ProofFields(c.ZK))
	if c.DeferPairing {
		c.PairingAccumulator = make([]frontend.Variable, protocol.AccumulatorFields)
	}
	if c.HashPublicInputs {
		c.HashedInputs = make([]frontend.Variable, n)
		c.PublicHash = make([]frontend.Variable, 1)
	} else {
		c.Public = make([]frontend.Variable, n)
	}
	return c, nil
}

func (c *Circuit) validateShape() ([]frontend.Variable, [3]int, error) {
	vk, dims, err := parseVK(c.VK)
	if err != nil {
		return nil, dims, err
	}
	n := dims[1] - protocol.AccumulatorFields
	if len(c.Proof) != protocol.ProofFields(c.ZK) {
		return nil, dims, fmt.Errorf("incorrect proof length")
	}
	if (c.DeferPairing && len(c.PairingAccumulator) != protocol.AccumulatorFields) || (!c.DeferPairing && len(c.PairingAccumulator) != 0) {
		return nil, dims, fmt.Errorf("incorrect deferred pairing output shape")
	}
	if c.HashPublicInputs {
		if len(c.Public) != 0 || len(c.HashedInputs) != n || len(c.PublicHash) != 1 {
			return nil, dims, fmt.Errorf("incorrect digest-profile inputs")
		}
	} else if len(c.Public) != n || len(c.HashedInputs) != 0 || len(c.PublicHash) != 0 {
		return nil, dims, fmt.Errorf("incorrect public input shape")
	}
	return vk, dims, nil
}

// Assignment parses canonical decimal or hexadecimal fields. In the digest
// profile it computes the single public hash; a verifier must authenticate that
// expected digest just as it would authenticate explicit public input values.
func (c *Circuit) Assignment(public, proof []string) (*Circuit, error) {
	return c.assignment(public, proof, nil)
}

// AssignmentWithDeferredPairing assigns externally computed final pairing
// points in P0.x.lo, P0.x.hi, P0.y.lo, P0.y.hi, P1.x.lo, ... order. The circuit
// constrains every limb to its own reduction; caller-supplied values are not
// trusted. It rejects use with a non-deferred circuit.
func (c *Circuit) AssignmentWithDeferredPairing(public, proof, accumulator []string) (*Circuit, error) {
	if !c.DeferPairing {
		return nil, fmt.Errorf("circuit does not defer pairing")
	}
	return c.assignment(public, proof, accumulator)
}

func (c *Circuit) assignment(public, proof, accumulator []string) (*Circuit, error) {
	_, dims, err := c.validateShape()
	if err != nil {
		return nil, err
	}
	if len(public) != dims[1]-protocol.AccumulatorFields || len(proof) != len(c.Proof) {
		return nil, fmt.Errorf("incorrect public input or proof length")
	}
	if len(accumulator) != len(c.PairingAccumulator) {
		return nil, fmt.Errorf("expected %d final pairing limbs; use AssignmentWithDeferredPairing for the deferred profile", len(c.PairingAccumulator))
	}
	var opts []Option
	if c.ZeroAccumulator {
		opts = append(opts, WithZeroAccumulator())
	}
	if c.HashPublicInputs {
		opts = append(opts, WithPublicInputHash())
	}
	if c.DeferPairing {
		opts = append(opts, WithDeferredPairing())
	}
	out, err := NewCircuit(c.VK, c.ZK, opts...)
	if err != nil {
		return nil, err
	}
	values := make([]*big.Int, len(public))
	target := out.Public
	if c.HashPublicInputs {
		target = out.HashedInputs
	}
	for i, s := range public {
		n, err := parseField(s)
		if err != nil {
			return nil, fmt.Errorf("public field %d: %w", i, err)
		}
		values[i] = n
		target[i] = n
	}
	if c.HashPublicInputs {
		hash, err := poseidon2.HashNative(values)
		if err != nil {
			return nil, err
		}
		out.PublicHash[0] = hash
	}
	for i, s := range proof {
		n, err := parseField(s)
		if err != nil {
			return nil, fmt.Errorf("proof field %d: %w", i, err)
		}
		out.Proof[i] = n
	}
	for i, s := range accumulator {
		n, err := parseField(s)
		if err != nil {
			return nil, fmt.Errorf("pairing limb %d: %w", i, err)
		}
		bits := 136
		if i%2 == 1 {
			bits = 118
		}
		if n.BitLen() > bits {
			return nil, fmt.Errorf("pairing limb %d exceeds %d bits", i, bits)
		}
		out.PairingAccumulator[i] = n
	}
	return out, nil
}

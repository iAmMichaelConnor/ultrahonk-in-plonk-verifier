// Package ultrahonk implements a fixed-verification-key Aztec v6 verifier.
package ultrahonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/pairing"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/poseidon2"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/scalar"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/transcript"
)

// Circuit is compiled for one authenticated VK, proof flavour and input profile.
// In the digest profile, HashedInputs holds the original application inputs and
// PublicHash has exactly one public field. Otherwise Public holds those inputs.
// With deferred pairing, PairingAccumulator exposes the final two G1 points.
// A verifier must discharge that equation outside the circuit before acceptance.
type Circuit struct {
	Public             []frontend.Variable `gnark:",public"`
	PublicHash         []frontend.Variable `gnark:",public"`
	PairingAccumulator []frontend.Variable `gnark:",public"`
	HashedInputs       []frontend.Variable
	Proof              []frontend.Variable
	VK                 []string `gnark:"-"`
	ZK                 bool     `gnark:"-"`
	ZeroAccumulator    bool     `gnark:"-"`
	HashPublicInputs   bool     `gnark:"-"`
	DeferPairing       bool     `gnark:"-"`
}

func (c *Circuit) Define(api frontend.API) error {
	return c.define(api, func(base *emulated.Field[sw_bn254.BaseField], p0, p1 *sw_bn254.G1Affine) error {
		if !c.DeferPairing {
			return pairing.Check(api, p0, p1)
		}
		for i, p := range []*sw_bn254.G1Affine{p0, p1} {
			for j, limb := range encodePoint(api, base, p) {
				api.AssertIsEqual(limb, c.PairingAccumulator[4*i+j])
			}
		}
		return nil
	})
}

// define derives the complete pairing equation, including the recursive merge.
// finish either checks it or binds it to public outputs. Keeping one reduction
// prevents the deferred profile from accidentally skipping an inner check.
func (c *Circuit) define(api frontend.API, finish func(*emulated.Field[sw_bn254.BaseField], *sw_bn254.G1Affine, *sw_bn254.G1Affine) error) error {
	if err := protocol.RequireNativeField(api); err != nil {
		return err
	}
	vk, dims, err := c.validateShape()
	if err != nil {
		return err
	}
	inputs := c.Public
	if c.HashPublicInputs {
		inputs = c.HashedInputs
		api.AssertIsEqual(poseidon2.Hash(api, inputs), c.PublicHash[0])
	}
	data := append(append([]frontend.Variable{}, inputs...), c.Proof...)
	proof, err := protocol.Parse(data, dims[1], c.ZK)
	if err != nil {
		return err
	}
	if c.ZeroAccumulator {
		for _, field := range proof.Accumulator() {
			api.AssertIsEqual(field, 0)
		}
	}
	challenges, err := transcript.Derive(api, poseidon2.Hash(api, vk), proof)
	if err != nil {
		return err
	}
	if err = scalar.Check(api, proof, dims[2], challenges); err != nil {
		return err
	}
	scalars, err := scalar.OpeningScalars(api, proof, challenges)
	if err != nil {
		return err
	}
	// Complete shared-window arithmetic handles the variable-point MSM.
	// Constant points use fixed-base combs; the recursive merge retains
	// gnark's checked GLV+fake-GLV path.
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	base, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return err
	}
	fr, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}
	decode := func(in protocol.Point) *sw_bn254.G1Affine { return decodePoint(api, base, curve, in) }

	encoded := proof.MSMPoints(vk)
	if len(encoded) != len(scalars) {
		return fmt.Errorf("point and scalar count mismatch")
	}
	fixedPoints := make([]*sw_bn254.G1Affine, 0, len(encoded)-1)
	fixedScalars := make([]*sw_bn254.Scalar, 0, len(encoded)-1)
	variablePoints := make([]*sw_bn254.G1Affine, 0, len(encoded)-1)
	variableScalars := make([]frontend.Variable, 0, len(encoded)-1)
	q, w := decode(proof.Q), decode(proof.W)
	for i := 1; i < len(encoded); i++ {
		var p *sw_bn254.G1Affine
		if i == len(encoded)-1 {
			p = w
		} else {
			p = decode(encoded[i])
		}
		// Only compiler constants qualify. Witness-controlled infinity points
		// stay in the MSM; omitting their scalar constraints would be unsafe.
		x, xok := base.ConstantValue(&p.X)
		y, yok := base.ConstantValue(&p.Y)
		if xok && yok && x.Sign() == 0 && y.Sign() == 0 {
			continue
		}
		if xok && yok {
			fixedPoints = append(fixedPoints, p)
			fixedScalars = append(fixedScalars, fr.FromBits(api.ToBinary(scalars[i], 254)...))
		} else {
			variablePoints = append(variablePoints, p)
			variableScalars = append(variableScalars, scalars[i])
		}
	}
	zero := emulated.ValueOf[sw_bn254.BaseField](0)
	sum := &sw_bn254.G1Affine{X: zero, Y: zero}
	if len(fixedPoints) > 0 {
		sum, err = curve.MultiScalarMul(fixedPoints, fixedScalars)
		if err != nil {
			return err
		}
	}
	if len(variablePoints) > 0 {
		variableSum, err := sharedMSM(api, curve, variablePoints, variableScalars, 5)
		if err != nil {
			return err
		}
		sum = curve.AddUnified(sum, variableSum)
	}
	// Q has coefficient one. All arithmetic remains complete at zero/infinity.
	p0, p1 := curve.AddUnified(q, sum), curve.Neg(w)
	isInfinity := func(p *sw_bn254.G1Affine) frontend.Variable { return api.And(base.IsZero(&p.X), base.IsZero(&p.Y)) }
	api.AssertIsEqual(isInfinity(p0), 0)
	api.AssertIsEqual(isInfinity(p1), 0)
	accum := proof.Accumulator()
	if c.ZeroAccumulator {
		// This is a compile-time specialization of the accepted input domain.
		return finish(base, p0, p1)
	}
	a0, a1 := decode(protocol.Point(accum[:4])), decode(protocol.Point(accum[4:]))
	inf := isInfinity(a0)
	api.AssertIsEqual(inf, isInfinity(a1))
	hashInput := append(append(append([]frontend.Variable{}, accum...), encodePoint(api, base, p0)...), encodePoint(api, base, p1)...)
	bits := api.ToBinary(poseidon2.Hash(api, hashInput), 254)
	sep := api.Select(inf, 1, api.FromBinary(bits[:127]...))
	sepEl := fr.FromBits(api.ToBinary(sep, 127)...)
	// The fake-GLV path does not benefit from WithNbScalarBits. Constrain
	// the separator's 127-bit bound explicitly above.
	p0 = curve.AddUnified(a0, curve.ScalarMul(p0, sepEl))
	p1 = curve.AddUnified(a1, curve.ScalarMul(p1, sepEl))
	return finish(base, p0, p1)
}

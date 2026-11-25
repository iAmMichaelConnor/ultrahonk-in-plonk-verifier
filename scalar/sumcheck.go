// Package scalar implements the Aztec v6 UltraHonk scalar sumcheck checks.
// These checks must be composed with the complete polynomial-opening verifier.
package scalar

import (
	"github.com/consensys/gnark/frontend"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

// Interpolate uses Newton's forward-difference formula, which is defined even
// when x equals an interpolation node. All factorial denominators are fixed.
func Interpolate(api frontend.API, values []frontend.Variable, x frontend.Variable) frontend.Variable {
	if len(values) < 1 || len(values) > 9 {
		panic("UltraHonk interpolation requires 1 to 9 values")
	}
	d := append([]frontend.Variable(nil), values...)
	coeff := make([]frontend.Variable, len(d))
	factorial := int64(1)
	for i := range d {
		if i > 0 {
			factorial *= int64(i)
		}
		coeff[i] = api.Mul(d[0], api.Inverse(factorial))
		for j := 0; j < len(d)-i-1; j++ {
			d[j] = api.Sub(d[j+1], d[j])
		}
	}
	out := coeff[len(coeff)-1]
	for i := len(coeff) - 2; i >= 0; i-- {
		out = api.Add(api.Mul(out, api.Sub(x, i)), coeff[i])
	}
	return out
}

// Check constrains the sumcheck and final relation. The proof fields and
// challenges must be bound to the same transcript and opening commitments.
func Check(api frontend.API, proof *protocol.Proof, publicOffset int, c protocol.Challenges) error {
	if err := protocol.RequireNativeField(api); err != nil {
		return err
	}
	num, den := frontend.Variable(1), frontend.Variable(1)
	for i, input := range proof.Public {
		num = api.Mul(num, api.Add(c.Gamma, input, api.Mul(c.Beta, 268435456+publicOffset+i)))
		den = api.Mul(den, api.Sub(api.Add(c.Gamma, input), api.Mul(c.Beta, publicOffset+i+1)))
	}
	delta := api.Div(num, den)
	target := frontend.Variable(0)
	if proof.ZK {
		target = api.Mul(proof.LibraSum, c.Libra)
	}
	gate, gateEval, disabled := c.Gate, frontend.Variable(1), frontend.Variable(1)
	for i, univ := range proof.Univariates {
		u := c.U[i]
		api.AssertIsEqual(api.Add(univ[0], univ[1]), target)
		target = Interpolate(api, univ, u)
		gateEval = api.Mul(gateEval, api.Add(1, api.Mul(u, api.Sub(gate, 1))))
		gate = api.Mul(gate, gate)
		if i >= 2 {
			disabled = api.Mul(disabled, api.Sub(1, u))
		}
	}
	var p [41]frontend.Variable
	if proof.ZK {
		copy(p[:], proof.Evaluations[1:])
	} else {
		copy(p[:], proof.Evaluations)
	}
	relation := Relations(api, p, c.Eta, c.RomLogupGamma, c.Beta, c.Gamma, delta, gateEval, c.Alpha)
	if proof.ZK {
		relation = api.Add(api.Mul(relation, api.Sub(1, disabled)), api.Mul(proof.LibraClaimed, c.Libra))
	}
	api.AssertIsEqual(target, relation)
	return nil
}

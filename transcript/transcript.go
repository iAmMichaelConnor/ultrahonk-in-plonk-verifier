// Package transcript derives Aztec v6 UltraHonk Fiat–Shamir challenges.
// Callers must additionally check the proof's algebraic and opening relations.
package transcript

import (
	"github.com/consensys/gnark/frontend"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/poseidon2"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

// Derive binds all protocol messages to a fixed or constrained VK hash.
func Derive(api frontend.API, vkHash frontend.Variable, p *protocol.Proof) (protocol.Challenges, error) {
	var c protocol.Challenges
	if err := protocol.RequireNativeField(api); err != nil {
		return c, err
	}
	pending := []frontend.Variable{vkHash}
	var previous frontend.Variable
	absorb := func(fields ...frontend.Variable) { pending = append(pending, fields...) }
	challenge := func() frontend.Variable {
		data := pending
		if previous != nil {
			data = append([]frontend.Variable{previous}, pending...)
		}
		previous = poseidon2.Hash(api, data)
		pending = nil
		return previous
	}
	absorb(p.Public...)
	if p.ZK {
		absorb(p.Mask[:]...)
	}
	absorb(p.WL[:]...)
	absorb(p.WR[:]...)
	absorb(p.WO[:]...)
	c.Eta = challenge()
	c.RomLogupGamma = challenge()
	absorb(p.Counts[:]...)
	absorb(p.Tags[:]...)
	absorb(p.W4[:]...)
	c.Beta = challenge()
	c.Gamma = challenge()
	absorb(p.Inverses[:]...)
	absorb(p.ZPerm[:]...)
	c.Alpha = challenge()
	c.Gate = challenge()
	if p.ZK {
		absorb(p.Concat[:]...)
		absorb(p.LibraSum)
		c.Libra = challenge()
	}
	for i, u := range p.Univariates {
		absorb(u...)
		c.U[i] = challenge()
	}
	absorb(p.Evaluations...)
	if p.ZK {
		absorb(p.LibraClaimed)
		absorb(p.Grand[:]...)
		absorb(p.Quot[:]...)
	}
	c.Rho = challenge()
	for _, fold := range p.Folds {
		absorb(fold[:]...)
	}
	c.R = challenge()
	absorb(p.Negative[:]...)
	if p.ZK {
		absorb(p.LibraEvaluations[:]...)
	}
	c.Nu = challenge()
	absorb(p.Q[:]...)
	c.Z = challenge()
	// W is the last opening witness. No further challenge is sampled.
	return c, nil
}

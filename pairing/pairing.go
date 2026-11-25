// Package pairing implements the final fixed-SRS pairing equation used by
// Aztec v6 UltraHonk. It is only one part of an UltraHonk verifier.
package pairing

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// Circuit checks e(P[0], G2) * e(P[1], [tau]G2) = 1. P must be derived
// inside a complete verifier, not accepted as proof of an UltraHonk statement.
// The G2 points and their precomputed lines are compile-time constants.
type Circuit struct{ P [2]sw_bn254.G1Affine }

// SRSPoints returns fresh native copies of the two fixed Aztec G2 points.
// Deferred verifiers must use these authenticated constants, not prover inputs.
func SRSPoints() [2]bn254.G2Affine {
	_, _, _, generator := bn254.Generators()
	var tau bn254.G2Affine
	tau.X.A0.SetString("496075682290949347282619629729389528669750910289829251317610107342504362928")
	tau.X.A1.SetString("17212635814319756364507010169094758005397460366678210664966334781961899574209")
	tau.Y.A0.SetString("15828724851114720558251891430452666121603726704878231219287131634746610441813")
	tau.Y.A1.SetString("2255182984359105691812395885056400739448730162863181907784180250290003009508")
	return [2]bn254.G2Affine{generator, tau}
}

func fixedG2() [2]sw_bn254.G2Affine {
	p := SRSPoints()
	return [2]sw_bn254.G2Affine{sw_bn254.NewG2AffineFixed(p[0]), sw_bn254.NewG2AffineFixed(p[1])}
}

func (c *Circuit) Define(api frontend.API) error {
	return Check(api, &c.P[0], &c.P[1])
}

// Check constrains the fixed Aztec SRS pairing equation.
func Check(api frontend.API, p0, p1 *sw_bn254.G1Affine) error {
	p, err := sw_bn254.NewPairing(api)
	if err != nil {
		return err
	}
	p.AssertIsOnG1(p0)
	p.AssertIsOnG1(p1)
	g2 := fixedG2()
	return p.PairingCheck([]*sw_bn254.G1Affine{p0, p1}, []*sw_bn254.G2Affine{&g2[0], &g2[1]})
}

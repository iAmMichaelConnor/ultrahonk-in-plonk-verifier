package pairing

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// Algebraic vectors, not a PLONK setup or proof. These check signs, bilinear
// grouping and the need for a post-commitment batching challenge.
func TestPLONKUltraHonkBatchEquation(t *testing.T) {
	_, _, g, q := bn254.Generators()
	g1 := func(n int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g, big.NewInt(n))
		return p
	}
	g2 := func(n int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&q, big.NewInt(n))
		return p
	}
	mul := func(p bn254.G1Affine, n int64) bn254.G1Affine {
		var r bn254.G1Affine
		r.ScalarMultiplication(&p, big.NewInt(n))
		return r
	}
	add := func(p, r bn254.G1Affine) bn254.G1Affine {
		var s bn254.G1Affine
		s.Add(&p, &r)
		return s
	}
	check := func(ps []bn254.G1Affine, qs []bn254.G2Affine, want bool) {
		t.Helper()
		ok, err := bn254.PairingCheck(ps, qs)
		if err != nil || ok != want {
			t.Fatalf("pairing=%v, want %v: %v", ok, want, err)
		}
	}
	const rho = 37 // Algebra test only. Real verifiers derive rho by Fiat-Shamir.
	for _, sharedSRS := range []bool{false, true} {
		tauOuter := int64(7)
		if sharedSRS {
			tauOuter = 13
		}
		tOuter, tInner := g2(tauOuter), g2(13)
		p, r := g1(19*tauOuter), g1(-19)
		u, v := g1(23*13), g1(-23)
		check([]bn254.G1Affine{p, r}, []bn254.G2Affine{q, tOuter}, true)
		check([]bn254.G1Affine{u, v}, []bn254.G2Affine{q, tInner}, true)
		left, right := add(p, mul(u, rho)), mul(v, rho)
		check([]bn254.G1Affine{left, r, right}, []bn254.G2Affine{q, tOuter, tInner}, true)
		if sharedSRS {
			check([]bn254.G1Affine{left, add(r, right)}, []bn254.G2Affine{q, tInner}, true)
		}
		// Both equations are false, yet their unweighted product is one.
		badP, badU := add(p, g1(-1)), add(u, g)
		check([]bn254.G1Affine{badP, r}, []bn254.G2Affine{q, tOuter}, false)
		check([]bn254.G1Affine{badU, v}, []bn254.G2Affine{q, tInner}, false)
		check([]bn254.G1Affine{add(badP, badU), r, v}, []bn254.G2Affine{q, tOuter, tInner}, true)
		check([]bn254.G1Affine{add(badP, mul(badU, rho)), r, mul(v, rho)}, []bn254.G2Affine{q, tOuter, tInner}, false)
	}
}

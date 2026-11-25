package ultrahonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// TestSharedMSMReviewBoundaries checks the production window width against
// native curve arithmetic. All cases share the same compiled two-point circuit.
func TestSharedMSMReviewBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("compiled shared MSM boundary review")
	}
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), scs.NewBuilder, &sharedMSMCircuit{
		P: make([]sw_bn254.G1Affine, 2), S: make([]frontend.Variable, 2), Width: 5,
	})
	if err != nil {
		t.Fatal(err)
	}

	var g, threeG, negG, infinity bn254.G1Affine
	g.ScalarMultiplicationBase(big.NewInt(1))
	threeG.ScalarMultiplicationBase(big.NewInt(3))
	negG.Neg(&g)
	infinity.SetInfinity()

	// phi(G) = (omega*x, y). G and -phi(G) have distinct X but their
	// Y coordinates sum to zero, so the Brier-Joye y-sum denominator is zero
	// although their sum is a finite point. Exercise this case explicitly.
	var omega fp.Element
	omega.SetBigInt(sw_emulated.GetBN254Params().ThirdRootOne)
	negPhiG := g
	negPhiG.X.Mul(&negPhiG.X, &omega)
	negPhiG.Y.Neg(&negPhiG.Y)
	var ySum fp.Element
	ySum.Add(&g.Y, &negPhiG.Y)
	if g.X.Equal(&negPhiG.X) || !ySum.IsZero() || !negPhiG.IsOnCurve() {
		t.Fatal("invalid cube-root exceptional-case fixture")
	}

	type reviewCase struct {
		name   string
		points [2]bn254.G1Affine
		s      [2]*big.Int
	}
	cases := []reviewCase{
		{"cube-root-opposite-y", [2]bn254.G1Affine{g, negPhiG}, [2]*big.Int{big.NewInt(1), big.NewInt(1)}},
		{"doubling", [2]bn254.G1Affine{g, g}, [2]*big.Int{big.NewInt(1), big.NewInt(1)}},
		{"cancellation", [2]bn254.G1Affine{g, negG}, [2]*big.Int{big.NewInt(33), big.NewInt(33)}},
		{"infinity-input", [2]bn254.G1Affine{infinity, threeG}, [2]*big.Int{big.NewInt(17), big.NewInt(31)}},
		{"zero-scalars", [2]bn254.G1Affine{g, threeG}, [2]*big.Int{big.NewInt(0), big.NewInt(0)}},
	}
	for _, boundary := range []int64{16, 17, 31, 32, 33} {
		cases = append(cases, reviewCase{
			"scalar-" + big.NewInt(boundary).String(), [2]bn254.G1Affine{g, threeG},
			[2]*big.Int{big.NewInt(boundary), big.NewInt(1)},
		})
	}
	carryChain := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 200), big.NewInt(1))
	cases = append(cases,
		reviewCase{"carry-chain-200-bits", [2]bn254.G1Affine{g, threeG}, [2]*big.Int{carryChain, big.NewInt(1)}},
		reviewCase{"bit-253", [2]bn254.G1Affine{g, threeG}, [2]*big.Int{new(big.Int).Lsh(big.NewInt(1), 253), big.NewInt(1)}},
		reviewCase{"modulus-minus-one", [2]bn254.G1Affine{g, threeG}, [2]*big.Int{new(big.Int).Sub(bn254.ID.ScalarField(), big.NewInt(1)), big.NewInt(1)}},
	)
	encode := func(p bn254.G1Affine) sw_bn254.G1Affine {
		return sw_bn254.G1Affine{X: emulated.ValueOf[sw_bn254.BaseField](p.X), Y: emulated.ValueOf[sw_bn254.BaseField](p.Y)}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &sharedMSMCircuit{P: make([]sw_bn254.G1Affine, 2), S: make([]frontend.Variable, 2)}
			var expected bn254.G1Affine
			expected.SetInfinity()
			for i := range tc.points {
				w.P[i], w.S[i] = encode(tc.points[i]), tc.s[i]
				var term bn254.G1Affine
				term.ScalarMultiplication(&tc.points[i], tc.s[i])
				expected.Add(&expected, &term)
			}
			if tc.name == "cube-root-opposite-y" && expected.IsInfinity() {
				t.Fatal("cube-root fixture must have a finite sum")
			}
			w.Result = encode(expected)
			witness, err := frontend.NewWitness(w, bn254.ID.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ccs.Solve(witness); err != nil {
				t.Fatalf("native MSM result rejected: %v", err)
			}

			// Add a nonzero generator to obtain a distinct valid expected point.
			// This changes only the claimed result, keeping the same inputs.
			var changed bn254.G1Affine
			changed.Add(&expected, &g)
			if changed.Equal(&expected) || !changed.IsOnCurve() {
				t.Fatal("invalid changed-result fixture")
			}
			w.Result = encode(changed)
			witness, err = frontend.NewWitness(w, bn254.ID.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ccs.Solve(witness); err == nil {
				t.Fatal("accepted changed result")
			}
		})
	}
	t.Run("off-curve-zero-contribution", func(t *testing.T) {
		offCurve := g
		offCurve.Y.SetOne()
		if offCurve.IsOnCurve() {
			t.Fatal("invalid off-curve fixture")
		}
		w := &sharedMSMCircuit{
			P: []sw_bn254.G1Affine{encode(offCurve), encode(g)},
			S: []frontend.Variable{0, 0}, Result: encode(infinity),
		}
		witness, err := frontend.NewWitness(w, bn254.ID.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ccs.Solve(witness); err == nil {
			t.Fatal("zero scalar bypassed input point validation")
		}
	})
}

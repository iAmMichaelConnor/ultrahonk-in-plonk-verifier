package scalar

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

type interpolationCircuit struct {
	Values      []frontend.Variable
	X, Expected frontend.Variable
}

func (c *interpolationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(Interpolate(api, c.Values, c.X), c.Expected)
	return nil
}
func TestInterpolationAtNodes(t *testing.T) {
	for _, n := range []int{8, 9} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &interpolationCircuit{Values: make([]frontend.Variable, n)})
		if err != nil {
			t.Fatal(err)
		}
		for x := 0; x <= n; x++ {
			a := interpolationCircuit{Values: make([]frontend.Variable, n), X: x}
			poly := func(i int) *big.Int {
				v := big.NewInt(int64(i))
				v.Exp(v, big.NewInt(int64(n-1)), protocol.ScalarModulus())
				return v.Add(v, big.NewInt(int64(3*i+7)))
			}
			for i := range a.Values {
				a.Values[i] = poly(i)
			}
			a.Expected = poly(x)
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = cs.Solve(w); err != nil {
				t.Fatalf("n=%d,x=%d: %v", n, x, err)
			}
		}
	}
}

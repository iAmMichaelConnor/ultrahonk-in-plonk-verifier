package ultrahonk

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type sharedMSMCircuit struct {
	P      []sw_bn254.G1Affine
	S      []frontend.Variable
	Result sw_bn254.G1Affine
	Width  int `gnark:"-"`
}

func (c *sharedMSMCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	points := make([]*sw_bn254.G1Affine, len(c.P))
	for i := range points {
		points[i] = &c.P[i]
		curve.AssertIsOnCurve(points[i])
	}
	result, err := sharedMSM(api, curve, points, c.S, c.Width)
	if err != nil {
		return err
	}
	curve.AssertIsEqual(result, &c.Result)
	return nil
}

func TestSharedMSM(t *testing.T) {
	if testing.Short() {
		t.Skip("compiled complete MSM regression")
	}
	const n = 2
	for _, width := range []int{2, 5, 6} {
		t.Run(fmt.Sprintf("width-%d", width), func(t *testing.T) {
			c := &sharedMSMCircuit{P: make([]sw_bn254.G1Affine, n), S: make([]frontend.Variable, n), Width: width}
			ccs, err := frontend.Compile(bn254.ID.ScalarField(), scs.NewBuilder, c)
			if err != nil {
				t.Fatal(err)
			}
			for k := 0; k < 5; k++ {
				w := &sharedMSMCircuit{P: make([]sw_bn254.G1Affine, n), S: make([]frontend.Variable, n)}
				var sum bn254.G1Affine
				for i := 0; i < n; i++ {
					var p, term bn254.G1Affine
					p.ScalarMultiplicationBase(big.NewInt(int64(i + 1)))
					h := sha256.Sum256([]byte(fmt.Sprintf("shared-msm/%d/%d", k, i)))
					s := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), bn254.ID.ScalarField())
					switch k {
					case 0:
						s.SetInt64(0)
					case 1:
						s.Sub(bn254.ID.ScalarField(), big.NewInt(1))
					case 2:
						s.Lsh(big.NewInt(1), 128)
						p.ScalarMultiplicationBase(big.NewInt(1))
						if i%2 == 1 {
							p.Neg(&p)
						}
					case 3:
						if i%3 == 0 {
							p.SetInfinity()
						}
						if i%3 == 1 {
							s.SetInt64(1)
						}
					}
					w.P[i] = sw_bn254.G1Affine{X: emulated.ValueOf[sw_bn254.BaseField](p.X), Y: emulated.ValueOf[sw_bn254.BaseField](p.Y)}
					w.S[i] = s
					term.ScalarMultiplication(&p, s)
					sum.Add(&sum, &term)
				}
				w.Result = sw_bn254.G1Affine{X: emulated.ValueOf[sw_bn254.BaseField](sum.X), Y: emulated.ValueOf[sw_bn254.BaseField](sum.Y)}
				witness, err := frontend.NewWitness(w, bn254.ID.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ccs.Solve(witness); err != nil {
					t.Fatalf("n=%d width=%d case=%d: %v", n, width, k, err)
				}
				var bad bn254.G1Affine
				bad.ScalarMultiplicationBase(big.NewInt(999))
				w.Result = sw_bn254.G1Affine{X: emulated.ValueOf[sw_bn254.BaseField](bad.X), Y: emulated.ValueOf[sw_bn254.BaseField](bad.Y)}
				witness, err = frontend.NewWitness(w, bn254.ID.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = ccs.Solve(witness); err == nil {
					t.Fatal("accepted altered result")
				}
			}
		})
	}
}

package ultrahonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

type decodeCircuit struct{ Point protocol.Point }

func (c *decodeCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[sw_bn254.BaseField, sw_bn254.ScalarField](api, sw_emulated.GetBN254Params())
	if err != nil {
		return err
	}
	base, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return err
	}
	decodePoint(api, base, curve, c.Point)
	return nil
}
func pointFields(x, y *big.Int) protocol.Point {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 136), big.NewInt(1))
	return protocol.Point{new(big.Int).And(x, mask), new(big.Int).Rsh(new(big.Int).Set(x), 136), new(big.Int).And(y, mask), new(big.Int).Rsh(new(big.Int).Set(y), 136)}
}
func TestCanonicalPointEncoding(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &decodeCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	q := fp.Modulus()
	cases := []struct {
		name  string
		p     protocol.Point
		valid bool
	}{
		{"infinity", protocol.Point{0, 0, 0, 0}, true}, {"generator", protocol.Point{1, 0, 2, 0}, true},
		{"off curve", protocol.Point{1, 0, 1, 0}, false},
		{"alias infinity", pointFields(q, big.NewInt(0)), false},
		{"alias generator X", pointFields(new(big.Int).Add(q, big.NewInt(1)), big.NewInt(2)), false},
		{"alias generator Y", pointFields(big.NewInt(1), new(big.Int).Add(q, big.NewInt(2))), false},
		{"wide low limb", protocol.Point{new(big.Int).Lsh(big.NewInt(1), 136), 0, 2, 0}, false},
		{"wide high limb", protocol.Point{1, new(big.Int).Lsh(big.NewInt(1), 118), 2, 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := frontend.NewWitness(&decodeCircuit{Point: tc.p}, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			_, err = cs.Solve(w)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

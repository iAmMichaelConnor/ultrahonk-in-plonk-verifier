package pairing

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
)

func fixture(t *testing.T) Circuit {
	t.Helper()
	raw, err := os.ReadFile("../testdata/pairing-points.json")
	if err != nil {
		t.Fatal(err)
	}
	var points [2][2]string
	if err := json.Unmarshal(raw, &points); err != nil {
		t.Fatal(err)
	}
	var c Circuit
	for i := range points {
		var p bn254.G1Affine
		if _, err := p.X.SetString(points[i][0]); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Y.SetString(points[i][1]); err != nil {
			t.Fatal(err)
		}
		c.P[i] = sw_bn254.NewG1Affine(p)
	}
	return c
}

func TestPairing(t *testing.T) {
	c := fixture(t)
	if err := test.IsSolved(&Circuit{}, &c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	_, _, g, _ := bn254.Generators()
	c.P[0] = sw_bn254.NewG1Affine(g)
	if err := test.IsSolved(&Circuit{}, &c, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted altered point")
	}
}

// Compile with the actual PLONK builder. Set FULL_PLONK_TEST=1 because this
// non-native pairing circuit requires substantial time and memory.
func TestPLONKConstraints(t *testing.T) {
	if os.Getenv("FULL_PLONK_TEST") != "1" {
		t.Skip("set FULL_PLONK_TEST=1")
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PLONK constraints: %d", cs.GetNbConstraints())
	assignment := fixture(t)
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
}

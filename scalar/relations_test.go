package scalar

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type solidityRelationsCircuit struct {
	P        [41]frontend.Variable
	Fields   [7]frontend.Variable
	Expected frontend.Variable
}

func (c *solidityRelationsCircuit) Define(api frontend.API) error {
	f := c.Fields
	api.AssertIsEqual(Relations(api, c.P, f[0], f[1], f[2], f[3], f[4], f[5], f[6]), c.Expected)
	return nil
}
func TestIndependentSolidityRelations(t *testing.T) {
	raw, err := os.ReadFile("testdata/solidity-relations.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		P        [41]string `json:"p"`
		Fields   [7]string  `json:"fields"`
		Expected string     `json:"expected"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &solidityRelationsCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for n, v := range vectors {
		a := solidityRelationsCircuit{Expected: v.Expected}
		for i, x := range v.P {
			a.P[i] = x
		}
		for i, x := range v.Fields {
			a.Fields[i] = x
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
	}
}

package poseidon2

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

type hashCircuit struct {
	In  []frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *hashCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(Hash(api, c.In), c.Out)
	return nil
}
func TestUpstreamVectors(t *testing.T) {
	raw, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Vectors []struct {
			Input  []string `json:"input"`
			Output string   `json:"output"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, v := range data.Vectors {
		shape := hashCircuit{In: make([]frontend.Variable, len(v.Input))}
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &shape)
		if err != nil {
			t.Fatal(err)
		}
		nativeValues := make([]*big.Int, len(v.Input))
		for i, x := range v.Input {
			nativeValues[i], _ = new(big.Int).SetString(x, 0)
		}
		native, err := HashNative(nativeValues)
		if err != nil {
			t.Fatal(err)
		}
		expected, ok := new(big.Int).SetString(v.Output, 0)
		if !ok || native.Cmp(expected) != 0 {
			t.Fatal("native hash differs from upstream vector")
		}
		assignment := hashCircuit{In: make([]frontend.Variable, len(v.Input)), Out: v.Output}
		for i, x := range v.Input {
			assignment.In[i] = x
		}
		w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err = cs.IsSolved(w); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeAndCircuitHash(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 6, 7} {
		values := make([]*big.Int, n)
		a := hashCircuit{In: make([]frontend.Variable, n)}
		for i := range values {
			values[i] = big.NewInt(int64(17*i + 3))
			a.In[i] = values[i]
		}
		expected, err := HashNative(values)
		if err != nil {
			t.Fatal(err)
		}
		a.Out = expected
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &hashCircuit{In: make([]frontend.Variable, n)})
		if err != nil {
			t.Fatal(err)
		}
		w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = cs.Solve(w); err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	for _, value := range []*big.Int{nil, big.NewInt(-1), protocol.ScalarModulus()} {
		if _, err := HashNative([]*big.Int{value}); err == nil {
			t.Fatal("accepted noncanonical native hash input")
		}
	}
}

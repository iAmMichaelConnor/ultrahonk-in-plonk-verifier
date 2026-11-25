package scalar

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

type libraCircuit struct {
	R, Claimed frontend.Variable
	U          [protocol.Rounds]frontend.Variable
	Evals      [4]frontend.Variable
}

func (c *libraCircuit) Define(api frontend.API) error {
	checkLibra(api, c.R, c.Evals, c.Claimed, protocol.Challenges{U: c.U})
	return nil
}
func TestLibraBinding(t *testing.T) {
	raw, err := os.ReadFile("../testdata/square-zk/trace.json")
	if err != nil {
		t.Fatal(err)
	}
	var tr struct {
		Challenges map[string]string
		Parsed     struct {
			Evals   []string `json:"libra_evaluations"`
			Claimed string   `json:"libra_claimed_evaluation"`
		}
	}
	if err = json.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	a := libraCircuit{R: tr.Challenges["r"], Claimed: tr.Parsed.Claimed}
	for i := range a.U {
		a.U[i] = tr.Challenges[fmt.Sprintf("u_%d", i)]
	}
	for i, x := range tr.Parsed.Evals {
		a.Evals[i] = x
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &libraCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	solve := func(c *libraCircuit) error {
		w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		_, err = cs.Solve(w)
		return err
	}
	if err = solve(&a); err != nil {
		t.Fatal(err)
	}
	for i := range a.Evals {
		b := a
		b.Evals[i] = 0
		if err = solve(&b); err == nil {
			t.Fatalf("accepted altered Libra evaluation %d", i)
		}
	}
	b := a
	b.Claimed = 0
	if err = solve(&b); err == nil {
		t.Fatal("accepted changed claimed evaluation")
	}
	b = a
	b.R = 1
	if err = solve(&b); err == nil {
		t.Fatal("accepted challenge in Libra subgroup")
	}
}

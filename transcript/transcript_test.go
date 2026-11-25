package transcript

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

type circuit struct {
	Proof    []frontend.Variable
	VK       frontend.Variable
	Expected []frontend.Variable
	Names    []string `gnark:"-"`
}

func (c *circuit) Define(api frontend.API) error {
	p, err := protocol.Parse(c.Proof, 9, true)
	if err != nil {
		return err
	}
	got, err := Derive(api, c.VK, p)
	if err != nil {
		return err
	}
	for i, v := range got.Ordered(true) {
		api.AssertIsEqual(v, c.Expected[i])
	}
	return nil
}
func TestZKTranscript(t *testing.T) {
	raw, err := os.ReadFile("../testdata/square-zk/trace.json")
	if err != nil {
		t.Fatal(err)
	}
	var tr struct {
		VK         string            `json:"vk_hash"`
		Proof      []string          `json:"proof"`
		Challenges map[string]string `json:"challenges"`
	}
	if err = json.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	names := []string{"eta", "rom_logup_gamma", "beta", "gamma", "alpha", "gate_challenge", "libra_challenge"}
	for i := 0; i < 25; i++ {
		names = append(names, fmt.Sprintf("u_%d", i))
	}
	names = append(names, "rho", "r", "nu", "z")
	shape := circuit{Proof: make([]frontend.Variable, len(tr.Proof)), Expected: make([]frontend.Variable, len(names)), Names: names}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &shape)
	if err != nil {
		t.Fatal(err)
	}
	assignment := circuit{Proof: make([]frontend.Variable, len(tr.Proof)), VK: tr.VK, Expected: make([]frontend.Variable, len(names)), Names: names}
	for i, x := range tr.Proof {
		assignment.Proof[i] = x
	}
	for i, n := range names {
		assignment.Expected[i] = tr.Challenges[n]
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
}

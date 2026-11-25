package scalar

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/transcript"
)

type openingCircuit struct {
	Proof    []frontend.Variable
	VK       frontend.Variable
	Expected []frontend.Variable
	ZK       bool `gnark:"-"`
}

func (c *openingCircuit) Define(api frontend.API) error {
	p, err := protocol.Parse(c.Proof, 9, c.ZK)
	if err != nil {
		return err
	}
	ch, err := transcript.Derive(api, c.VK, p)
	if err != nil {
		return err
	}
	scalars, err := OpeningScalars(api, p, ch)
	if err != nil {
		return err
	}
	if len(scalars) != len(c.Expected) {
		panic("bad output length")
	}
	for i := range scalars {
		api.AssertIsEqual(scalars[i], c.Expected[i])
	}
	return nil
}
func TestOpeningScalars(t *testing.T) {
	for _, tc := range []struct {
		name string
		zk   bool
	}{{"square-zk", true}, {"square-non-zk", false}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("../testdata/" + tc.name + "/trace.json")
			if err != nil {
				t.Fatal(err)
			}
			var tr struct {
				VK      string   `json:"vk_hash"`
				Proof   []string `json:"proof"`
				Scalars []string `json:"msm_scalars"`
			}
			if err = json.Unmarshal(raw, &tr); err != nil {
				t.Fatal(err)
			}
			shape := openingCircuit{Proof: make([]frontend.Variable, len(tr.Proof)), Expected: make([]frontend.Variable, len(tr.Scalars)), ZK: tc.zk}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &shape)
			if err != nil {
				t.Fatal(err)
			}
			a := openingCircuit{Proof: make([]frontend.Variable, len(tr.Proof)), Expected: make([]frontend.Variable, len(tr.Scalars)), VK: tr.VK, ZK: tc.zk}
			for i, x := range tr.Proof {
				a.Proof[i] = x
			}
			for i, x := range tr.Scalars {
				a.Expected[i] = x
			}
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err = cs.IsSolved(w); err != nil {
				t.Fatal(err)
			}
		})
	}
}

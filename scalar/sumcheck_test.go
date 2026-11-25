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

type scalarCircuit struct {
	Proof       []frontend.Variable
	VK          frontend.Variable
	ZK          bool `gnark:"-"`
	PublicCount int  `gnark:"-"`
}

func (c *scalarCircuit) Define(api frontend.API) error {
	p, err := protocol.Parse(c.Proof, c.PublicCount, c.ZK)
	if err != nil {
		return err
	}
	ch, err := transcript.Derive(api, c.VK, p)
	if err != nil {
		return err
	}
	return Check(api, p, protocol.PublicOffset, ch)
}
func TestSumcheckFixtures(t *testing.T) {
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
				VK    string   `json:"vk_hash"`
				Proof []string `json:"proof"`
			}
			if err = json.Unmarshal(raw, &tr); err != nil {
				t.Fatal(err)
			}
			shape := scalarCircuit{Proof: make([]frontend.Variable, len(tr.Proof)), ZK: tc.zk, PublicCount: 9}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &shape)
			if err != nil {
				t.Fatal(err)
			}
			a := scalarCircuit{Proof: make([]frontend.Variable, len(tr.Proof)), VK: tr.VK, ZK: tc.zk, PublicCount: 9}
			for i, x := range tr.Proof {
				a.Proof[i] = x
			}
			w, err := frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err = cs.IsSolved(w); err != nil {
				t.Fatal(err)
			}
			a.Proof[0] = 50
			w, err = frontend.NewWitness(&a, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err = cs.IsSolved(w); err == nil {
				t.Fatal("accepted altered public input")
			}
		})
	}
}

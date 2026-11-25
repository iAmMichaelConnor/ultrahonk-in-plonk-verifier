package ultrahonk

import (
	"encoding/json"
	"math/big"
	"os"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

func fixture(t *testing.T, name string, zk bool, opts ...Option) (*Circuit, *Circuit) {
	t.Helper()
	var key struct {
		VK []string `json:"vk"`
	}
	var proof struct {
		Proof []string `json:"proof"`
	}
	var pubs struct {
		Inputs []string `json:"public_inputs"`
	}
	for _, item := range []struct {
		file string
		dst  any
	}{{"vk.json", &key}, {"proof.json", &proof}, {"public_inputs.json", &pubs}} {
		b, err := os.ReadFile("../testdata/" + name + "/" + item.file)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, item.dst); err != nil {
			t.Fatal(err)
		}
	}
	shape, err := NewCircuit(key.VK, zk, opts...)
	if err != nil {
		t.Fatal(err)
	}
	var a *Circuit
	if shape.DeferPairing {
		// The test-only oracle constructs the public outputs before solving
		// the actual SCS circuit, which independently binds every output.
		base := *shape
		base.DeferPairing = false
		base.PairingAccumulator = nil
		input, inputErr := base.Assignment(pubs.Inputs, proof.Proof)
		if inputErr != nil {
			t.Fatal(inputErr)
		}
		limbs := capture(t, &base, input)
		a, err = shape.AssignmentWithDeferredPairing(pubs.Inputs, proof.Proof, limbs)
	} else {
		a, err = shape.Assignment(pubs.Inputs, proof.Proof)
	}
	if err != nil {
		t.Fatal(err)
	}
	return shape, a
}

// Routine tests include the full composition for both flavours. -short skips
// these high-memory checks; CI runs the ordinary and extended gates explicitly.
func TestVerifierEngine(t *testing.T) {
	if testing.Short() {
		t.Skip("complete verifier integration test")
	}
	cases := []struct {
		name string
		zk   bool
	}{{"square-non-zk", false}, {"square-zk", true}}
	if os.Getenv("FULL_VERIFIER_TEST") == "1" {
		cases = append(cases, struct {
			name string
			zk   bool
		}{"recursive", true}, struct {
			name string
			zk   bool
		}{"root-rollup", false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shape, a := fixture(t, tc.name, tc.zk)
			if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
		runtime.GC()
	}
}

func TestVerifierProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("complete verifier profile test")
	}
	cases := []struct {
		name     string
		zk, zero bool
	}{{"square-non-zk", false, true}}
	if os.Getenv("FULL_VERIFIER_TEST") == "1" {
		cases = append(cases, struct {
			name     string
			zk, zero bool
		}{"square-zk", true, true}, struct {
			name     string
			zk, zero bool
		}{"recursive", true, false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := []Option{WithPublicInputHash()}
			if tc.zero {
				opts = append(opts, WithZeroAccumulator())
			}
			shape, a := fixture(t, tc.name, tc.zk, opts...)
			if len(shape.Public) != 0 || len(shape.PublicHash) != 1 {
				t.Fatal("expected one outer public field")
			}
			if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
		})
		runtime.GC()
	}
}

func TestDigestBinding(t *testing.T) {
	shape, a := fixture(t, "square-non-zk", false, WithPublicInputHash(), WithZeroAccumulator())
	digest := a.PublicHash[0]
	a.PublicHash[0] = new(big.Int).Add(digest.(*big.Int), big.NewInt(1))
	if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted changed public digest")
	}
	a.PublicHash[0] = digest
	a.HashedInputs[0] = 50
	if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted changed original application input")
	}
}

func TestZeroProfileRejectsRecursiveAccumulator(t *testing.T) {
	shape, a := fixture(t, "recursive", true, WithZeroAccumulator())
	if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted nonzero accumulator in zero profile")
	}
}

func TestWrongFixedKey(t *testing.T) {
	shape, a := fixture(t, "square-non-zk", false)
	copy(shape.VK[3:7], []string{"1", "0", "2", "0"})
	if err := test.IsSolved(shape, a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted a different fixed VK")
	}
}

func TestVerifierPLONKConstraints(t *testing.T) {
	if os.Getenv("FULL_PLONK_TEST") != "1" {
		t.Skip("set FULL_PLONK_TEST=1")
	}
	name := os.Getenv("PLONK_FIXTURE")
	if name == "" {
		name = "square-non-zk"
	}
	zk := name == "square-zk" || name == "recursive"
	var opts []Option
	if os.Getenv("PLONK_PROFILE") == "zero" {
		opts = append(opts, WithZeroAccumulator())
	}
	if os.Getenv("PLONK_PUBLIC_INPUTS") == "hash" {
		opts = append(opts, WithPublicInputHash())
	}
	shape, a := fixture(t, name, zk, opts...)
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, shape)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PLONK constraints: %d", cs.GetNbConstraints())
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cs.Solve(w); err != nil {
		t.Fatal(err)
	}
	if shape.HashPublicInputs {
		a.PublicHash[0] = 0
	} else {
		a.Public[0] = 50
	}
	w, err = frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cs.Solve(w); err == nil {
		t.Fatal("accepted altered outer public input")
	}
}

func TestVerifierRejectsMutations(t *testing.T) {
	if os.Getenv("FULL_NEGATIVE_TEST") == "" {
		t.Skip("set FULL_NEGATIVE_TEST=1 for SCS or engine for lower-memory checks")
	}
	for _, tc := range []struct {
		name string
		zk   bool
	}{{"square-non-zk", false}, {"square-zk", true}, {"recursive", true}} {
		t.Run(tc.name, func(t *testing.T) {
			shape, a := fixture(t, tc.name, tc.zk)
			check := func(c *Circuit) error { return test.IsSolved(shape, c, ecc.BN254.ScalarField()) }
			if os.Getenv("FULL_NEGATIVE_TEST") != "engine" {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, shape)
				if err != nil {
					t.Fatal(err)
				}
				check = func(c *Circuit) error {
					w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
					if err != nil {
						return err
					}
					_, err = cs.Solve(w)
					return err
				}
			}
			l, err := protocol.NewLayout(len(a.Public)+protocol.AccumulatorFields, tc.zk)
			if err != nil {
				t.Fatal(err)
			}
			offset := func(s protocol.Span) int { return s.Start - len(a.Public) }
			cases := []struct {
				name   string
				change func(*Circuit)
			}{
				{"application input", func(c *Circuit) { c.Public[0] = 50 }},
				{"one-sided accumulator", func(c *Circuit) { copy(c.Proof[:8], []frontend.Variable{1, 0, 2, 0, 0, 0, 0, 0}) }},
				{"commitment coordinate", func(c *Circuit) { c.Proof[offset(l.WL)] = 1 }},
				{"sumcheck univariate", func(c *Circuit) { c.Proof[offset(l.Univariates[0])] = 1 }},
				// W is not hashed into any challenge. A valid replacement
				// must reach the final opening/pairing checks and be rejected.
				{"valid-curve opening witness", func(c *Circuit) { copy(c.Proof[offset(l.W):offset(l.W)+4], []frontend.Variable{1, 0, 2, 0}) }},
			}
			if tc.zk {
				cases = append(cases, struct {
					name   string
					change func(*Circuit)
				}{"Libra evaluation", func(c *Circuit) {
					i := offset(l.LibraEvaluations)
					c.Proof[i] = new(big.Int).Add(c.Proof[i].(*big.Int), big.NewInt(1))
				}})
			}
			if tc.name == "recursive" {
				cases = append(cases, struct {
					name   string
					change func(*Circuit)
				}{"different populated accumulator", func(c *Circuit) { copy(c.Proof[:8], []frontend.Variable{1, 0, 2, 0, 1, 0, 2, 0}) }})
			}
			for _, mut := range cases {
				t.Run(mut.name, func(t *testing.T) {
					copyA := *a
					copyA.Public = append([]frontend.Variable(nil), a.Public...)
					copyA.Proof = append([]frontend.Variable(nil), a.Proof...)
					mut.change(&copyA)
					if err := check(&copyA); err == nil {
						t.Fatal("accepted mutated input")
					}
				})
			}
		})
		runtime.GC()
	}
}

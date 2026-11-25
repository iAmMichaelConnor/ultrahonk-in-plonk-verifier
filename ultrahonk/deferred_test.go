package ultrahonk

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/pairing"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

// capturePairing is a test-engine oracle for witness construction only. It is
// never compiled into a proof: production circuits bind all eight output limbs.
type capturePairing struct {
	Inner  Circuit
	Output *[]string `gnark:"-"`
}

func (c *capturePairing) Define(api frontend.API) error {
	return c.Inner.define(api, func(base *emulated.Field[sw_bn254.BaseField], p0, p1 *sw_bn254.G1Affine) error {
		var limbs []string
		for _, p := range []*sw_bn254.G1Affine{p0, p1} {
			for _, v := range encodePoint(api, base, p) {
				n, ok := api.Compiler().ConstantValue(v)
				if !ok {
					return fmt.Errorf("capturePairing requires the test engine")
				}
				limbs = append(limbs, n.String())
			}
		}
		*c.Output = limbs
		return nil
	})
}

func capture(t *testing.T, shape, a *Circuit) []string {
	t.Helper()
	var out []string
	if err := test.IsSolved(&capturePairing{Inner: *shape, Output: &out}, &capturePairing{Inner: *a, Output: &out}, ecc.BN254.ScalarField(), test.SetAllVariablesAsConstants()); err != nil {
		t.Fatal(err)
	}
	return out
}

func checkDeferred(limbs []string) (bool, error) {
	var p [2]bn254.G1Affine
	for i := range p {
		x, _ := new(big.Int).SetString(limbs[4*i], 10)
		xhi, _ := new(big.Int).SetString(limbs[4*i+1], 10)
		y, _ := new(big.Int).SetString(limbs[4*i+2], 10)
		yhi, _ := new(big.Int).SetString(limbs[4*i+3], 10)
		x.Add(x, xhi.Lsh(xhi, 136))
		y.Add(y, yhi.Lsh(yhi, 136))
		p[i].X.SetBigInt(x)
		p[i].Y.SetBigInt(y)
	}
	q := pairing.SRSPoints()
	return bn254.PairingCheck(p[:], q[:])
}

func TestDeferredPairing(t *testing.T) {
	if testing.Short() {
		t.Skip("complete deferred verifier test")
	}
	cases := []struct {
		name     string
		zk, zero bool
	}{{"square-non-zk", false, true}, {"root-rollup", false, false}}
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
			original, a := fixture(t, tc.name, tc.zk, opts...)
			limbs := capture(t, original, a)
			ok, err := checkDeferred(limbs)
			if err != nil || !ok {
				t.Fatalf("native deferred pairing: %v, %v", ok, err)
			}
			opts = append(opts, WithDeferredPairing())
			shape, err := NewCircuit(original.VK, tc.zk, opts...)
			if err != nil {
				t.Fatal(err)
			}
			pub, proof := make([]string, len(a.HashedInputs)), make([]string, len(a.Proof))
			for i, v := range a.HashedInputs {
				pub[i] = fmt.Sprint(v)
			}
			for i, v := range a.Proof {
				proof[i] = fmt.Sprint(v)
			}
			if _, err = shape.Assignment(pub, proof); err == nil {
				t.Fatal("accepted missing deferred points")
			}
			assigned, err := shape.AssignmentWithDeferredPairing(pub, proof, limbs)
			if err != nil {
				t.Fatal(err)
			}
			public, err := frontend.NewWitness(assigned, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatal(err)
			}
			if len(public.Vector().(fr.Vector)) != 9 {
				t.Fatal("expected one digest and eight pairing limbs")
			}
			check := func(a *Circuit) error { return test.IsSolved(shape, a, ecc.BN254.ScalarField()) }
			if os.Getenv("DEFERRED_SCS_TEST") == "1" {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, shape)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("deferred SCS constraints: %d", cs.GetNbConstraints())
				check = func(a *Circuit) error {
					w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
					if err != nil {
						return err
					}
					_, err = cs.Solve(w)
					return err
				}
			}
			if err = check(assigned); err != nil {
				t.Fatal(err)
			}
			// Change each output independently: even canonical small limb values
			// cannot be substituted for the circuit's computed pairing points.
			for i := range assigned.PairingAccumulator {
				old := assigned.PairingAccumulator[i]
				assigned.PairingAccumulator[i] = new(big.Int).Add(old.(*big.Int), big.NewInt(1))
				if err = check(assigned); err == nil {
					t.Fatalf("accepted changed pairing limb %d", i)
				}
				assigned.PairingAccumulator[i] = old
			}
			// A valid-curve W mutation passes all pre-pairing algebra. The
			// deferred circuit may accept its NEW points, but L1 must reject.
			layout, err := protocol.NewLayout(len(pub)+protocol.AccumulatorFields, tc.zk)
			if err != nil {
				t.Fatal(err)
			}
			start := layout.W.Start - len(pub)
			copy(a.Proof[start:start+4], []frontend.Variable{big.NewInt(1), big.NewInt(0), big.NewInt(2), big.NewInt(0)})
			bad := capture(t, original, a)
			ok, err = checkDeferred(bad)
			if err == nil && ok {
				t.Fatal("L1 pairing accepted changed opening witness")
			}
			for i := range bad {
				assigned.PairingAccumulator[i], _ = new(big.Int).SetString(bad[i], 10)
			}
			copy(assigned.Proof[start:start+4], a.Proof[start:start+4])
			if err = check(assigned); err != nil {
				t.Fatalf("deferred boundary: %v", err)
			}
		})
		runtime.GC()
	}
}

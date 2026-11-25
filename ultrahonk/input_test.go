package ultrahonk

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

func TestCanonicalFieldParsing(t *testing.T) {
	for _, s := range []string{"0", "00049", "0x0031"} {
		if _, err := parseField(s); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"-1", "+1", "0x", "0xgg", "21888242871839275222246405745257275088548364400416034343698204186575808495617"} {
		if _, err := parseField(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestConstructorAndAssignment(t *testing.T) {
	shape, assignment := fixture(t, "square-non-zk", false)
	c, err := NewCircuit(shape.VK, false)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]string, len(assignment.Proof))
	for i, v := range assignment.Proof {
		p[i] = fmt.Sprint(v)
	}
	pub := []string{fmt.Sprint(assignment.Public[0])}
	if _, err = c.Assignment(pub, p); err != nil {
		t.Fatal(err)
	}
	p[0] = "-1"
	if _, err = c.Assignment(pub, p); err == nil {
		t.Fatal("accepted negative field")
	}
	if _, err = c.Assignment(nil, p); err == nil {
		t.Fatal("accepted wrong public input count")
	}
}

func TestUnsupportedFieldAndShape(t *testing.T) {
	c, _ := fixture(t, "square-non-zk", false)
	if _, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, c); err == nil {
		t.Fatal("accepted unsupported native field")
	}
	bad := append([]string(nil), c.VK...)
	bad[1] = fmt.Sprint(protocol.MaxPublicInputs + 1)
	if _, err := NewCircuit(bad, false); err == nil {
		t.Fatal("constructor accepted unsupported dimensions")
	}
	copyC := *c
	copyC.VK = bad
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &copyC); err == nil {
		t.Fatal("Define accepted dimensions rejected by constructor")
	}
	c.PublicHash = []frontend.Variable{0}
	if _, err := c.Assignment([]string{"49"}, make([]string, len(c.Proof))); err == nil {
		t.Fatal("assignment accepted mismatched shape")
	}
}

func TestDigestAssignmentShape(t *testing.T) {
	c, a := fixture(t, "square-non-zk", false, WithPublicInputHash(), WithZeroAccumulator())
	if len(a.Public) != 0 || len(a.PublicHash) != 1 || len(a.HashedInputs) != 1 || !a.ZeroAccumulator || !a.HashPublicInputs {
		t.Fatal("incorrect profile shape")
	}
	public, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if len(public.Vector().(fr.Vector)) != 1 {
		t.Fatal("digest profile must expose exactly one public input")
	}
	mutated := new(big.Int).Set(protocol.ScalarModulus())
	mutated.SetInt64(1)
	if _, err := parseField(protocol.ScalarModulus().String()); err == nil {
		t.Fatal("accepted Fr modulus")
	}
	c.PublicHash = append(c.PublicHash, 0)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c); err == nil {
		t.Fatal("accepted extra digest field")
	}
}

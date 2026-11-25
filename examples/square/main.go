// Check the retained square witness, with optional PLONK proving.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/aztecsrs"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/ultrahonk"
)

func main() {
	fixture := flag.String("fixture", "testdata/square-non-zk", "directory containing the Barretenberg square fixture")
	prove := flag.Bool("prove", false, "run PLONK setup, prove, and verify using the Aztec ceremony")
	flag.Parse()

	if err := run(*fixture, *prove); err != nil {
		log.Fatal(err)
	}
}

func run(dir string, prove bool) error {
	var key struct {
		Fields []string `json:"vk"`
	}
	var input struct {
		Public []string `json:"public_inputs"`
	}
	var proof struct {
		Fields []string `json:"proof"`
	}
	for name, destination := range map[string]any{
		"vk.json": &key, "public_inputs.json": &input, "proof.json": &proof,
	} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, destination); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
	}
	shape, err := ultrahonk.NewCircuit(key.Fields, false)
	if err != nil {
		return err
	}
	assignment, err := shape.Assignment(input.Public, proof.Fields)
	if err != nil {
		return err
	}
	field := ecc.BN254.ScalarField()
	if !prove {
		if err := test.IsSolved(shape, assignment, field); err != nil {
			return err
		}
		fmt.Println("Square witness satisfies the verifier in gnark's test engine")
		return nil
	}

	circuit, err := frontend.Compile(field, scs.NewBuilder, shape)
	if err != nil {
		return err
	}
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return err
	}
	domain := ecc.NextPowerOfTwo(uint64(circuit.GetNbConstraints() + circuit.GetNbPublicVariables()))
	canonical, lagrange, _, err := aztecsrs.LoadCached("", "build/srs-cache", domain, func(s string) { log.Print(s) })
	if err != nil {
		return err
	}
	provingKey, verifyingKey, err := plonk.Setup(circuit, canonical, lagrange)
	if err != nil {
		return err
	}
	outerProof, err := plonk.Prove(circuit, provingKey, witness)
	if err != nil {
		return err
	}
	public, err := witness.Public()
	if err != nil {
		return err
	}
	if err := plonk.Verify(outerProof, verifyingKey, public); err != nil {
		return err
	}
	fmt.Println("Square PLONK proof verified")
	return nil
}

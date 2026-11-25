// Verify the retained root-rollup proof against its expected public inputs.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/pairing"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/poseidon2"
)

func main() {
	if err := verify(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Root-rollup PLONK proof, public-input digest and deferred pairing verified")
}

func verify() error {
	const fixture = "testdata/root-rollup"
	proof := plonk.NewProof(ecc.BN254)
	key := plonk.NewVerifyingKey(ecc.BN254)
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	for name, destination := range map[string]io.ReaderFrom{
		"proof.bin":          proof,
		"verifying-key.bin":  key,
		"public-witness.bin": public,
	} {
		data, err := os.ReadFile(filepath.Join(fixture, "outer-proof", name))
		if err != nil {
			return err
		}
		reader := bytes.NewReader(data)
		if _, err := destination.ReadFrom(reader); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		if reader.Len() != 0 {
			return fmt.Errorf("trailing data in %s", name)
		}
	}
	values := public.Vector().(fr.Vector)
	if len(values) != 9 {
		return fmt.Errorf("expected one digest and eight pairing limbs")
	}
	expected, err := expectedDigest(filepath.Join(fixture, "public_inputs.json"))
	if err != nil {
		return err
	}
	if values[0].BigInt(new(big.Int)).Cmp(expected) != 0 {
		return fmt.Errorf("unexpected public-input digest")
	}
	if err := plonk.Verify(proof, key, public); err != nil {
		return fmt.Errorf("verify outer proof: %w", err)
	}

	var points [2]bn254.G1Affine
	for i := range points {
		x, err := coordinate(values[1+4*i : 3+4*i])
		if err != nil {
			return err
		}
		y, err := coordinate(values[3+4*i : 5+4*i])
		if err != nil {
			return err
		}
		points[i].X.SetBigInt(x)
		points[i].Y.SetBigInt(y)
		if !points[i].IsOnCurve() {
			return fmt.Errorf("deferred pairing point %d is off curve", i)
		}
	}
	srs := pairing.SRSPoints()
	ok, err := bn254.PairingCheck(points[:], srs[:])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("deferred pairing check failed")
	}
	return nil
}

func expectedDigest(path string) (*big.Int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fixture struct {
		Inputs []string `json:"public_inputs"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return nil, err
	}
	inputs := make([]*big.Int, len(fixture.Inputs))
	for i, field := range fixture.Inputs {
		value, ok := new(big.Int).SetString(field, 0)
		if !ok {
			return nil, fmt.Errorf("invalid application input %d", i)
		}
		inputs[i] = value
	}
	return poseidon2.HashNative(inputs)
}

func coordinate(limbs fr.Vector) (*big.Int, error) {
	var low, high big.Int
	limbs[0].BigInt(&low)
	limbs[1].BigInt(&high)
	if low.BitLen() > 136 || high.BitLen() > 118 {
		return nil, fmt.Errorf("invalid deferred coordinate limbs")
	}
	coord := low.Add(&low, high.Lsh(&high, 136))
	if coord.Cmp(fp.Modulus()) >= 0 {
		return nil, fmt.Errorf("noncanonical deferred coordinate")
	}
	return coord, nil
}

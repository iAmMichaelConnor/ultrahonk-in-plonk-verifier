package aztecsrs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type square struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *square) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

func TestGnarkPLONKCompatibility(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &square{})
	if err != nil {
		t.Fatal(err)
	}
	domain := ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints() + cs.GetNbPublicVariables()))
	cacheDir := t.TempDir()
	_, _, _, err = LoadCached("testdata", cacheDir, domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, l, info, err := LoadCached("testdata", cacheDir, domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !info.CacheHit {
		t.Fatal("PLONK compatibility test must exercise the validated cache hit")
	}
	pk, vk, err := plonk.Setup(cs, c, l)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&square{X: 7, Y: 49}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	p, err := plonk.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err = plonk.Verify(p, vk, pub); err != nil {
		t.Fatal(err)
	}
	wrong, err := frontend.NewWitness(&square{Y: 50}, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = plonk.Verify(p, vk, wrong); err == nil {
		t.Fatal("accepted changed public statement")
	}
}

func files(t *testing.T) ([]byte, []byte) {
	t.Helper()
	a, err := os.ReadFile("testdata/bn254_g1.dat")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/bn254_g2.dat")
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}
func writeFiles(t *testing.T, dir string, g1, g2 []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"bn254_g1.dat": g1, "bn254_g2.dat": g2} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActualCeremonyPrefix(t *testing.T) {
	canonical, lagrange, info, err := Load("testdata", 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical.Pk.G1) != 11 || len(lagrange.Pk.G1) != 8 {
		t.Fatal("incorrect SRS dimensions")
	}
	g1, _ := files(t)
	digest := sha256.Sum256(g1[:11*64])
	if info.PrefixSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("prefix hash differs from raw Aztec encoding")
	}
	poly := make([]fr.Element, 8)
	for i := range poly {
		poly[i].SetUint64(uint64(i*i + 3))
	}
	commit, err := kzg.Commit(poly, canonical.Pk)
	if err != nil {
		t.Fatal(err)
	}
	evals := append([]fr.Element(nil), poly...)
	fft.NewDomain(8).FFT(evals, fft.DIF)
	fft.BitReverse(evals)
	lagrangeCommit, err := kzg.Commit(evals, lagrange.Pk)
	if err != nil {
		t.Fatal(err)
	}
	if !commit.Equal(&lagrangeCommit) {
		t.Fatal("Lagrange commitment differs from canonical commitment")
	}
	var z fr.Element
	z.SetUint64(7)
	proof, err := kzg.Open(poly, z, canonical.Pk)
	if err != nil {
		t.Fatal(err)
	}
	if err = kzg.Verify(&commit, &proof, z, canonical.Vk); err != nil {
		t.Fatal(err)
	}
	proof.ClaimedValue.Add(&proof.ClaimedValue, new(fr.Element).SetOne())
	if err = kzg.Verify(&commit, &proof, z, canonical.Vk); err == nil {
		t.Fatal("accepted altered KZG evaluation")
	}
}

func TestRejectMalformedOrInconsistentCRS(t *testing.T) {
	for _, name := range []string{"G2 order", "G2 changed", "noncanonical coordinate", "off curve", "infinity", "wrong generator", "middle power", "last blinding power", "partial point", "too small"} {
		t.Run(name, func(t *testing.T) {
			g1, g2 := files(t)
			switch name {
			case "G2 order":
				copy(g2[:64], append(append([]byte{}, g2[32:64]...), g2[:32]...))
			case "G2 changed":
				g2[127] ^= 1
			case "noncanonical coordinate":
				copy(g1[64:96], fp.Modulus().FillBytes(make([]byte, 32)))
			case "off curve":
				g1[127] ^= 1
			case "infinity":
				clear(g1[64:128])
			case "wrong generator":
				copy(g1[:64], g1[64:128])
			case "middle power":
				copy(g1[4*64:5*64], g1[3*64:4*64])
			case "last blinding power":
				copy(g1[10*64:11*64], g1[9*64:10*64])
			case "partial point":
				g1 = g1[:len(g1)-1]
			case "too small":
				g1 = g1[:8*64]
			}
			dir := t.TempDir()
			writeFiles(t, dir, g1, g2)
			if _, _, _, err := Load(dir, 8, nil); err == nil {
				t.Fatal("accepted malformed or inconsistent CRS")
			}
		})
	}
}

func TestSelectLargerCacheAndDomainBounds(t *testing.T) {
	dir := t.TempDir()
	g1, g2 := files(t)
	writeFiles(t, dir, g1[:8*64], g2)
	writeFiles(t, filepath.Join(dir, "bn254-4gib"), g1, g2)
	_, _, info, err := Load(dir, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.G1Path != filepath.Join(dir, "bn254-4gib", "bn254_g1.dat") {
		t.Fatal("did not select larger cache")
	}
	for _, domain := range []uint64{0, 1, 3, 1 << 29} {
		if _, _, _, err := Load(dir, domain, nil); err == nil {
			t.Fatalf("accepted domain %d", domain)
		}
	}
}

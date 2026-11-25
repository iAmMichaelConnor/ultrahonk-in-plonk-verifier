package ultrahonk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/aztecsrs"
	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

type proverMeasurement struct {
	G1Algorithm              string        `json:"g1_algorithm"`
	DeferredPairing          bool          `json:"deferred_pairing"`
	Ceremony                 aztecsrs.Info `json:"aztec_ceremony_srs"`
	Fixture                  string        `json:"fixture"`
	Accumulator              string        `json:"accumulator_profile"`
	PublicMode               string        `json:"public_mode"`
	ApplicationInputs        int           `json:"application_inputs"`
	OuterPublicInputs        int           `json:"outer_public_inputs"`
	Constraints              int           `json:"constraints"`
	Domain                   uint64        `json:"domain"`
	WitnessEncodingSeconds   float64       `json:"witness_encoding_seconds"`
	WitnessSolveSeconds      float64       `json:"witness_solve_seconds"`
	ProveSeconds             float64       `json:"prove_seconds_including_fresh_solve"`
	VerifySeconds            float64       `json:"verify_seconds"`
	CompileSeconds           float64       `json:"excluded_compile_seconds"`
	SetupSeconds             float64       `json:"excluded_setup_seconds"`
	ProofVerified            bool          `json:"proof_verified"`
	ChangedStatementRejected bool          `json:"changed_statement_rejected"`
	Artifacts                string        `json:"artifacts"`
}

type ceremonyPair struct {
	canonical, lagrange *kzg.SRS
	info                aztecsrs.Info
}

var ceremonyCache = struct {
	sync.Mutex
	entries map[string]ceremonyPair
}{entries: make(map[string]ceremonyPair)}

func ceremonyForTest(t *testing.T, domain uint64) ceremonyPair {
	t.Helper()
	dir, err := aztecsrs.DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%s/%d", dir, domain)
	ceremonyCache.Lock()
	defer ceremonyCache.Unlock()
	if pair, ok := ceremonyCache.entries[key]; ok {
		return pair
	}
	c, l, info, err := aztecsrs.LoadCached(dir, "../build/srs-cache", domain, func(s string) { t.Log(s) })
	if err != nil {
		t.Fatal(err)
	}
	pair := ceremonyPair{c, l, info}
	ceremonyCache.entries[key] = pair
	return pair
}

func writeArtifact(t *testing.T, path string, v io.WriterTo) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.WriteTo(f)
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func measureProver(t *testing.T, name string, opts ...Option) proverMeasurement {
	t.Helper()
	shape, a := fixture(t, name, false, opts...)
	result := proverMeasurement{Fixture: name, Accumulator: "general", PublicMode: "explicit", G1Algorithm: "complete shared 5-bit Horner MSM; fixed-base comb; checked GLV+fake-GLV merge"}
	result.DeferredPairing = shape.DeferPairing
	if shape.ZeroAccumulator {
		result.Accumulator = "zero"
	}
	if shape.HashPublicInputs {
		result.PublicMode = "Poseidon2 digest"
	}
	if shape.HashPublicInputs {
		result.ApplicationInputs = len(shape.HashedInputs)
	} else {
		result.ApplicationInputs = len(shape.Public)
	}
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, shape)
	if err != nil {
		t.Fatal(err)
	}
	result.CompileSeconds = time.Since(start).Seconds()
	result.Constraints = cs.GetNbConstraints()
	result.Domain = ecc.NextPowerOfTwo(uint64(result.Constraints + cs.GetNbPublicVariables()))
	start = time.Now()
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	result.WitnessEncodingSeconds = time.Since(start).Seconds()
	start = time.Now()
	if _, err = cs.Solve(w); err != nil {
		t.Fatal(err)
	}
	result.WitnessSolveSeconds = time.Since(start).Seconds()
	t.Logf("%s/%s/%s: constraints=%d, witness=%.3fs", name, result.Accumulator, result.PublicMode, result.Constraints, result.WitnessSolveSeconds)
	runtime.GC()
	start = time.Now()
	// Cache the imported and checked ceremony representation in memory.
	pair := ceremonyForTest(t, result.Domain)
	result.Ceremony = pair.info
	pk, vk, err := plonk.Setup(cs, pair.canonical, pair.lagrange)
	if err != nil {
		t.Fatal(err)
	}
	result.SetupSeconds = time.Since(start).Seconds()
	start = time.Now()
	proof, err := plonk.Prove(cs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	result.ProveSeconds = time.Since(start).Seconds()
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	result.OuterPublicInputs = len(pub.Vector().(fr.Vector))
	expectedPublic := 1
	if shape.DeferPairing {
		expectedPublic += protocol.AccumulatorFields
	}
	if shape.HashPublicInputs && result.OuterPublicInputs != expectedPublic {
		t.Fatal("incorrect number of digest and pairing public inputs")
	}
	start = time.Now()
	if err = plonk.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	result.VerifySeconds = time.Since(start).Seconds()
	result.ProofVerified = true
	if shape.DeferPairing {
		limbs := make([]string, len(a.PairingAccumulator))
		for i, v := range a.PairingAccumulator {
			limbs[i] = fmt.Sprint(v)
		}
		ok, err := checkDeferred(limbs)
		if err != nil || !ok {
			t.Fatalf("deferred Aztec pairing: %v, %v", ok, err)
		}
		// A valid outer proof must also bind the eight deferred coordinates.
		old := a.PairingAccumulator[0]
		a.PairingAccumulator[0] = new(big.Int).Add(old.(*big.Int), big.NewInt(1))
		changed, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			t.Fatal(err)
		}
		if err = plonk.Verify(proof, vk, changed); err == nil {
			t.Fatal("outer proof accepted altered deferred coordinates")
		}
		a.PairingAccumulator[0] = old
	}
	// Reuse the generated proof against a different outer statement.
	var original frontend.Variable
	if shape.HashPublicInputs {
		original = a.PublicHash[0]
		a.PublicHash[0] = new(big.Int).Mod(new(big.Int).Add(original.(*big.Int), big.NewInt(1)), protocol.ScalarModulus())
	} else {
		original = a.Public[0]
		a.Public[0] = new(big.Int).Mod(new(big.Int).Add(original.(*big.Int), big.NewInt(1)), protocol.ScalarModulus())
	}
	wrong, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err = plonk.Verify(proof, vk, wrong); err == nil {
		t.Fatal("outer proof accepted a different public statement")
	}
	result.ChangedStatementRejected = true
	if err = os.MkdirAll("../build/evidence", 0755); err != nil {
		t.Fatal(err)
	}
	out, err := os.MkdirTemp("../build/evidence", "prover-")
	if err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(out, "proof.bin"), proof)
	writeArtifact(t, filepath.Join(out, "verifying-key.bin"), vk)
	writeArtifact(t, filepath.Join(out, "public-witness.bin"), pub)
	result.Artifacts = strings.TrimPrefix(filepath.ToSlash(out), "../")
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "measurement.json"), append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: PLONK Prove=%.3fs, verified; artifacts=%s", name, result.ProveSeconds, result.Artifacts)
	return result
}

func sourceDigest(t *testing.T) string {
	t.Helper()
	var files []string
	for _, dir := range []string{"ultrahonk", "scalar", "transcript", "protocol", "poseidon2", "pairing", "aztecsrs"} {
		found, err := filepath.Glob(filepath.Join("..", dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range found {
			if !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
		}
	}
	files = append(files, "../go.mod", "../go.sum", "../poseidon2/constants.json", "../reference/aztec/sources.json")
	sort.Strings(files)
	hash := sha256.New()
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(hash, "%s\x00", strings.TrimPrefix(filepath.ToSlash(p), "../"))
		hash.Write(b)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeTimingReport(t *testing.T, measurements []proverMeasurement, output string) {
	t.Helper()
	var report bytes.Buffer
	fmt.Fprintln(&report, "# Aztec ceremony SRS UltraHonk-in-PLONK prover timings")
	fmt.Fprintf(&report, "\nMeasured %s with gnark v0.16.4 and %s on %s/%s. This is one run per configuration on a shared machine.\n", time.Now().UTC().Format(time.RFC3339), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if cpu, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(cpu), "\n") {
			if strings.HasPrefix(line, "model name") {
				fmt.Fprintf(&report, "\nCPU: %s.\n", strings.TrimSpace(strings.SplitN(line, ":", 2)[1]))
				break
			}
		}
	}
	fmt.Fprintf(&report, "\nLogical CPUs visible: %d; GOMAXPROCS: %d.\n", runtime.NumCPU(), runtime.GOMAXPROCS(0))
	if quota, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fmt.Fprintf(&report, "CPU quota (`cpu.max`): `%s`.\n", strings.TrimSpace(string(quota)))
	}
	fmt.Fprintln(&report, "\nCompilation, CRS import and validation, Lagrange conversion, and PLONK setup are excluded from the measurements below. Witness generation means solving the complete constraint witness, not just encoding the input values. Fixture parsing and native construction of expected public pairing outputs happen before these timers.")
	fmt.Fprintln(&report, "\nThe opening G1 MSM uses a shared five-bit Horner accumulator with complete additions. Constants use gnark's fixed-base comb and the recursive merge uses checked GLV+fake-GLV.")
	fmt.Fprintln(&report, "\n| Fixture | Accumulator | Pairing | Public inputs | Constraints | Domain | Input encoding | Witness generation | PLONK Prove |")
	fmt.Fprintln(&report, "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |")
	for _, m := range measurements {
		pairingMode := "in circuit"
		if m.DeferredPairing {
			pairingMode = "deferred to L1"
		}
		fmt.Fprintf(&report, "| %s | %s | %s | %d → %d (%s) | %d | %d | %.3f ms | %.3f s | %.3f s |\n", m.Fixture, m.Accumulator, pairingMode, m.ApplicationInputs, m.OuterPublicInputs, m.PublicMode, m.Constraints, m.Domain, 1000*m.WitnessEncodingSeconds, m.WitnessSolveSeconds, m.ProveSeconds)
	}
	fmt.Fprintln(&report, "\n`plonk.Prove` runs a fresh constraint solve internally and overlaps it with other proving work. Its elapsed time therefore includes that solve. The standalone witness and prover times are separate observations and should not be added or subtracted to infer a proof-only time.")
	fmt.Fprintln(&report, "\nEach actual outer PLONK proof was verified, and reusing it with a different public statement was rejected. The SRS is imported from the local Aztec ceremony cache. Every loaded G1 coordinate is canonical and on curve, the G2 point matches the fixed UltraHonk SRS, and every consecutive canonical power is checked in a randomized batch pairing. No toxic waste or generated test SRS is used. Raw measurements identify the exact prefix hashes and domain.")
	fmt.Fprintln(&report, "\nFor deferred profiles, the outer proof rejects changed public pairing coordinates. An independent native pairing checks the UltraHonk equation. The root-rollup fixture has 113 application inputs, a nonzero recursive accumulator and synthetic child proofs.")
	for _, m := range measurements {
		fmt.Fprintf(&report, "\nSRS for `%s`: `%s`; %d canonical powers; prefix SHA-256 `%s`; G2 file SHA-256 `%s`.\n", m.Fixture, m.Ceremony.G1Path, m.Ceremony.Powers, m.Ceremony.PrefixSHA256, m.Ceremony.G2SHA256)
		if m.Ceremony.CachePath != "" {
			fmt.Fprintf(&report, "\nPersistent Lagrange cache: `%s`; cache hit: %t. Cache loading, algebraic authentication and writes are setup work and are excluded above.\n", m.Ceremony.CachePath, m.Ceremony.CacheHit)
		}
	}
	command := "make timings"
	if output == "ceremony-timings.md" {
		command = "make timings-aztec"
	}
	fmt.Fprintf(&report, "\nReproduce:\n\n```sh\n%s\n```\n\nSerialized proofs, verifying keys, public witnesses and raw measurements:\n", command)
	for _, m := range measurements {
		fmt.Fprintf(&report, "\n- `%s`: [%s](%s/measurement.json).", m.Fixture, m.Artifacts, filepath.Base(m.Artifacts))
	}
	fmt.Fprintf(&report, "\n\nProduction source digest (SHA-256): `%s`.\n", sourceDigest(t))
	if err := os.WriteFile(filepath.Join("..", "build", "evidence", output), report.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

// This generates real PLONK proofs. Compilation and setup are deliberately
// outside the witness and proving timers. Ordinary tests skip this heavy run.
func TestProverTimings(t *testing.T) {
	if os.Getenv("FULL_PROOF_TEST") != "1" {
		t.Skip("set FULL_PROOF_TEST=1")
	}
	var results []proverMeasurement
	for _, tc := range []struct {
		name, label string
		opts        []Option
	}{
		{"square-non-zk", "general", nil},
		{"square-non-zk", "zero-digest", []Option{WithZeroAccumulator(), WithPublicInputHash()}},
		{"root-rollup", "general-digest", []Option{WithPublicInputHash()}},
	} {
		t.Run(tc.label, func(t *testing.T) { results = append(results, measureProver(t, tc.name, tc.opts...)) })
		if t.Failed() {
			t.FailNow()
		}
		runtime.GC()
	}
	writeTimingReport(t, results, "prover-timings.md")
}

func TestDeferredCeremonyProver(t *testing.T) {
	if os.Getenv("FULL_PROOF_TEST") != "1" {
		t.Skip("set FULL_PROOF_TEST=1")
	}
	m := measureProver(t, "root-rollup", WithPublicInputHash(), WithDeferredPairing())
	writeTimingReport(t, []proverMeasurement{m}, "ceremony-timings.md")
}

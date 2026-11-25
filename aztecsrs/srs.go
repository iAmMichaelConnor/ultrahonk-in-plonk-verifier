// Package aztecsrs adapts the cached Aztec BN254 ceremony to gnark KZG.
package aztecsrs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/pairing"
)

// Info identifies the exact canonical prefix used, not an entire larger file.
// The hash is computed from the loaded points after canonical decoding.
type Info struct {
	G1Path            string  `json:"g1_path"`
	G2Path            string  `json:"g2_path"`
	Powers            uint64  `json:"canonical_powers"`
	Domain            uint64  `json:"lagrange_domain"`
	PrefixSHA256      string  `json:"canonical_prefix_sha256"`
	G2SHA256          string  `json:"g2_file_sha256"`
	LoadSeconds       float64 `json:"load_seconds"`
	CheckSeconds      float64 `json:"all_powers_check_seconds"`
	LagrangeSeconds   float64 `json:"lagrange_seconds"`
	CachePath         string  `json:"lagrange_cache_path,omitempty"`
	CacheHit          bool    `json:"lagrange_cache_hit"`
	CacheCheckSeconds float64 `json:"lagrange_cache_check_seconds,omitempty"`
	CacheWriteSeconds float64 `json:"lagrange_cache_write_seconds,omitempty"`
}

// DefaultDir honors AZTEC_CRS_DIR, otherwise returns ~/.bb-crs.
func DefaultDir() (string, error) {
	if dir := os.Getenv("AZTEC_CRS_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".bb-crs"), nil
}

// Load reads domain+3 canonical powers and derives domain Lagrange powers.
// Both SRS objects share the fixed G2 generator and pinned Aztec tau point.
// Every coordinate is canonical, every G1 power is finite and on curve, and
// one randomized batched pairing checks EVERY consecutive power, including the
// three blinding powers. No toxic waste is used or inferred. progress may be nil.
// Conversion is intentionally in memory: no large derived cache is written.
func Load(root string, domain uint64, progress func(string)) (*kzg.SRS, *kzg.SRS, Info, error) {
	return load(root, "", domain, progress)
}

// LoadCached uses a persistent Lagrange cache under cacheDir. Canonical powers
// are still loaded and checked. Each cache hit checks every Lagrange point and
// a fresh randomized MSM identity against those canonical powers. Corrupt cache
// entries return an error; they are not silently trusted or overwritten.
func LoadCached(root, cacheDir string, domain uint64, progress func(string)) (*kzg.SRS, *kzg.SRS, Info, error) {
	if cacheDir == "" {
		return nil, nil, Info{}, fmt.Errorf("Lagrange cache directory must not be empty")
	}
	return load(root, cacheDir, domain, progress)
}

func load(root, cacheDir string, domain uint64, progress func(string)) (*kzg.SRS, *kzg.SRS, Info, error) {
	var info Info
	fail := func(err error) (*kzg.SRS, *kzg.SRS, Info, error) { return nil, nil, info, err }
	if domain < 2 || domain&(domain-1) != 0 || domain > 1<<28 {
		return fail(fmt.Errorf("unsupported BN254 domain %d", domain))
	}
	if root == "" {
		var err error
		root, err = DefaultDir()
		if err != nil {
			return fail(err)
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return fail(err)
	}
	info.Domain, info.Powers = domain, domain+3
	for _, dir := range []string{root, filepath.Join(root, "bn254-4gib")} {
		p := filepath.Join(dir, "bn254_g1.dat")
		stat, err := os.Stat(p)
		if err != nil {
			continue
		}
		if stat.Size()%64 != 0 {
			return fail(fmt.Errorf("G1 file %s has a partial point", p))
		}
		if stat.Size()/64 >= int64(info.Powers) {
			info.G1Path = p
			info.G2Path = filepath.Join(dir, "bn254_g2.dat")
			break
		}
	}
	if info.G1Path == "" {
		return fail(fmt.Errorf("Aztec CRS under %s needs at least %d G1 powers (%d bytes)", root, info.Powers, info.Powers*64))
	}
	log := func(s string) {
		if progress != nil {
			progress(s)
		}
	}
	start := time.Now()
	log(fmt.Sprintf("loading %d Aztec G1 powers from %s", info.Powers, info.G1Path))
	g2, err := readG2(info.G2Path)
	if err != nil {
		return fail(err)
	}
	h2 := sha256.Sum256(g2)
	info.G2SHA256 = hex.EncodeToString(h2[:])
	canonical := &kzg.SRS{}
	fixed := pairing.SRSPoints()
	canonical.Vk.G2 = fixed
	_, _, generator, _ := bn254.Generators()
	canonical.Vk.G1 = generator
	canonical.Vk.Lines[0] = bn254.PrecomputeLines(fixed[0])
	canonical.Vk.Lines[1] = bn254.PrecomputeLines(fixed[1])
	canonical.Pk.G1, err = readG1(info.G1Path, int(info.Powers))
	if err != nil {
		return fail(err)
	}
	if !canonical.Pk.G1[0].Equal(&generator) {
		return fail(fmt.Errorf("Aztec G1 powers must begin with the standard generator"))
	}
	hash := sha256.New()
	for i := range canonical.Pk.G1 {
		b := canonical.Pk.G1[i].RawBytes()
		hash.Write(b[:])
	}
	info.PrefixSHA256 = hex.EncodeToString(hash.Sum(nil))
	info.LoadSeconds = time.Since(start).Seconds()
	log("checking every consecutive Aztec power by randomized batched pairing")
	start = time.Now()
	if err = checkPowers(canonical); err != nil {
		return fail(err)
	}
	info.CheckSeconds = time.Since(start).Seconds()
	// Release random coefficients and MSM scratch before the group FFT.
	runtime.GC()
	start = time.Now()
	lagrange, err := lagrangeSRS(canonical, cacheDir, &info, log)
	if err != nil {
		return fail(err)
	}
	info.LagrangeSeconds = time.Since(start).Seconds()
	runtime.GC()
	log("Aztec ceremony SRS ready")
	return canonical, lagrange, info, nil
}

func readG2(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != 128 {
		return nil, fmt.Errorf("Aztec G2 file must contain one 128-byte tau point")
	}
	var tau bn254.G2Affine
	// Aztec raw order is A0,A1 for each Fp2 coordinate. gnark's G2 wire
	// encoding uses A1,A0, so do not call G2Affine.SetBytes on this file.
	if err = tau.X.A0.SetBytesCanonical(b[:32]); err != nil {
		return nil, err
	}
	if err = tau.X.A1.SetBytesCanonical(b[32:64]); err != nil {
		return nil, err
	}
	if err = tau.Y.A0.SetBytesCanonical(b[64:96]); err != nil {
		return nil, err
	}
	if err = tau.Y.A1.SetBytesCanonical(b[96:]); err != nil {
		return nil, err
	}
	fixed := pairing.SRSPoints()
	if !tau.Equal(&fixed[1]) || !tau.IsOnCurve() || !tau.IsInSubGroup() {
		return nil, fmt.Errorf("Aztec G2 tau point does not match the pinned UltraHonk SRS")
	}
	return b, nil
}

func readG1(path string, count int) ([]bn254.G1Affine, error) {
	return readPoints(path, count, false)
}

func readPoints(path string, count int, allowInfinity bool) ([]bn254.G1Affine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	points := make([]bn254.G1Affine, count)
	const chunk = 8192
	workers := min(runtime.GOMAXPROCS(0), 32)
	var next atomic.Int64
	var failed atomic.Bool
	var firstErr error
	var once sync.Once
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Go(func() {
			buf := make([]byte, 64*chunk)
			for !failed.Load() {
				start := int(next.Add(chunk)) - chunk
				if start >= count {
					return
				}
				n := min(chunk, count-start)
				if _, err := io.ReadFull(io.NewSectionReader(f, int64(start)*64, int64(n)*64), buf[:n*64]); err != nil {
					once.Do(func() { firstErr = err; failed.Store(true) })
					return
				}
				for j := 0; j < n; j++ {
					p := &points[start+j]
					raw := buf[64*j : 64*(j+1)]
					err := p.X.SetBytesCanonical(raw[:32])
					if err == nil {
						err = p.Y.SetBytesCanonical(raw[32:])
					}
					if err == nil && ((!allowInfinity && p.IsInfinity()) || (!p.IsInfinity() && !p.IsOnCurve())) {
						err = fmt.Errorf("point is infinity or off curve")
					}
					if err != nil {
						once.Do(func() { firstErr = fmt.Errorf("Aztec G1 power %d: %w", start+j, err); failed.Store(true) })
						return
					}
				}
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return points, nil
}

func checkPowers(srs *kzg.SRS) error {
	n := len(srs.Pk.G1) - 1
	coeffs, err := randomScalars(n)
	if err != nil {
		return err
	}
	return checkPowerMSMs(srs, coeffs)
}

func randomScalars(n int) ([]fr.Element, error) {
	coeffs := make([]fr.Element, n)
	// Batch entropy reads avoid a system call per power. Reduction of 256-bit
	// samples has at most 6/2^256 point probability; the error bound remains
	// negligible. Coefficients are fresh and independent of untrusted files.
	const chunk = 8192
	buf := make([]byte, 32*chunk)
	for start := 0; start < n; start += chunk {
		count := min(chunk, n-start)
		if _, err := rand.Read(buf[:32*count]); err != nil {
			return nil, err
		}
		for j := 0; j < count; j++ {
			coeffs[start+j].SetBytes(buf[32*j : 32*(j+1)])
		}
	}
	return coeffs, nil
}

func checkPowerMSMs(srs *kzg.SRS, coeffs []fr.Element) error {
	n := len(coeffs)
	var left, right bn254.G1Affine
	if _, err := left.MultiExp(srs.Pk.G1[1:], coeffs, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	if _, err := right.MultiExp(srs.Pk.G1[:n], coeffs, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	right.Neg(&right)
	// The native fixed-Q Miller loop mutates its line evaluations. Preserve
	// the canonical key's reusable precomputation by passing a value copy.
	lines := srs.Vk.Lines
	ok, err := bn254.PairingCheckFixedQ([]bn254.G1Affine{left, right}, lines[:])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Aztec G1 consecutive powers are inconsistent with the pinned tau G2 point")
	}
	return nil
}

package aztecsrs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func lagrangeSRS(canonical *kzg.SRS, cacheDir string, info *Info, log func(string)) (*kzg.SRS, error) {
	lagrange := &kzg.SRS{Vk: canonical.Vk}
	if cacheDir != "" {
		name := fmt.Sprintf("lagrange-v1-bn254-n%d-p%s-q%s.raw", info.Domain, info.PrefixSHA256, info.G2SHA256)
		path, err := filepath.Abs(filepath.Join(cacheDir, name))
		if err != nil {
			return nil, err
		}
		info.CachePath = path
		stat, err := os.Stat(path)
		if err == nil {
			if stat.Size() != int64(info.Domain)*64 {
				return nil, fmt.Errorf("Lagrange cache %s has incorrect length", path)
			}
			log(fmt.Sprintf("loading %d cached Lagrange G1 points from %s", info.Domain, path))
			// Infinity is a valid group element for the identity check. This
			// differs from canonical powers, which must all be finite.
			lagrange.Pk.G1, err = readPoints(path, int(info.Domain), true)
			if err != nil {
				return nil, fmt.Errorf("read Lagrange cache: %w", err)
			}
			log("checking every cached Lagrange point against the canonical SRS by randomized MSM")
			start := time.Now()
			if err = checkLagrange(canonical.Pk.G1[:int(info.Domain)], lagrange.Pk.G1); err != nil {
				return nil, fmt.Errorf("validate Lagrange cache %s: %w", path, err)
			}
			info.CacheCheckSeconds = time.Since(start).Seconds()
			info.CacheHit = true
			return lagrange, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	log(fmt.Sprintf("deriving %d Lagrange G1 points by inverse group FFT", info.Domain))
	var err error
	lagrange.Pk.G1, err = kzg.ToLagrangeG1(canonical.Pk.G1[:int(info.Domain)])
	if err != nil {
		return nil, err
	}
	if info.CachePath != "" {
		log(fmt.Sprintf("writing Lagrange cache to %s", info.CachePath))
		start := time.Now()
		if err = writeLagrange(info.CachePath, lagrange.Pk.G1); err != nil {
			return nil, err
		}
		info.CacheWriteSeconds = time.Since(start).Seconds()
	}
	return lagrange, nil
}

// L_i = sum_j omega^(-i*j) P_j / n. For fresh random r_i, check
// sum_i r_i L_i = sum_j IFFT(r)_j P_j. Thus every cached point is bound to the
// checked canonical SRS, with error at most 6/2^256 for any fixed wrong vector.
// No cache-supplied digest is treated as an authentication root.
func checkLagrange(canonical, lagrange []bn254.G1Affine) error {
	if len(canonical) != len(lagrange) || len(canonical) < 2 || len(canonical)&(len(canonical)-1) != 0 {
		return fmt.Errorf("invalid Lagrange check dimensions")
	}
	coeffs, err := randomScalars(len(lagrange))
	if err != nil {
		return err
	}
	var left, right bn254.G1Affine
	if _, err = left.MultiExp(lagrange, coeffs, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	fft.NewDomain(uint64(len(coeffs))).FFTInverse(coeffs, fft.DIF)
	fft.BitReverse(coeffs)
	if _, err = right.MultiExp(canonical, coeffs, ecc.MultiExpConfig{}); err != nil {
		return err
	}
	if !left.Equal(&right) {
		return fmt.Errorf("cached Lagrange points do not match the canonical ceremony powers")
	}
	return nil
}

func writeLagrange(path string, points []bn254.G1Affine) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".lagrange-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	out := bufio.NewWriterSize(f, 1<<20)
	for i := range points {
		raw := points[i].RawBytes()
		if _, err = out.Write(raw[:]); err != nil {
			return err
		}
	}
	if err = out.Flush(); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

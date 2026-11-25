package aztecsrs

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

func TestLagrangeCacheReuse(t *testing.T) {
	dir := t.TempDir()
	_, first, a, err := LoadCached("testdata", dir, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.CacheHit || a.CachePath == "" {
		t.Fatal("first load must create the cache")
	}
	_, second, b, err := LoadCached("testdata", dir, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !b.CacheHit || a.CachePath != b.CachePath || b.CacheCheckSeconds <= 0 {
		t.Fatal("second load must validate and reuse the same cache")
	}
	for i := range first.Pk.G1 {
		if !first.Pk.G1[i].Equal(&second.Pk.G1[i]) {
			t.Fatal("cached Lagrange basis differs")
		}
	}
	_, _, other, err := LoadCached("testdata", dir, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if other.CacheHit || a.CachePath == other.CachePath {
		t.Fatal("domains must use separate cache entries")
	}
	if files, err := filepath.Glob(filepath.Join(dir, ".lagrange-*.tmp")); err != nil || len(files) != 0 {
		t.Fatalf("temporary cache file remains: %v %v", files, err)
	}
	if _, _, _, err := LoadCached("testdata", "", 8, nil); err == nil {
		t.Fatal("accepted empty cache directory")
	}
}

func TestRejectCorruptLagrangeCache(t *testing.T) {
	for _, name := range []string{"first point", "middle point", "last point", "permutation preserving sum", "all infinity", "monomial basis", "noncanonical", "off curve", "truncated", "oversized"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			canonical, _, info, err := LoadCached("testdata", dir, 8, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(info.CachePath)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "first point", "middle point", "last point":
				index := map[string]int{"first point": 0, "middle point": 4, "last point": 7}[name]
				_, _, generator, _ := bn254.Generators()
				encoded := generator.RawBytes()
				copy(raw[index*64:(index+1)*64], encoded[:])
			case "permutation preserving sum":
				first := append([]byte(nil), raw[:64]...)
				copy(raw[:64], raw[64:128])
				copy(raw[64:128], first)
			case "all infinity":
				clear(raw)
			case "monomial basis":
				for i := 0; i < 8; i++ {
					encoded := canonical.Pk.G1[i].RawBytes()
					copy(raw[i*64:(i+1)*64], encoded[:])
				}
			case "noncanonical":
				copy(raw[:32], fp.Modulus().FillBytes(make([]byte, 32)))
			case "off curve":
				clear(raw[:64])
				raw[31], raw[63] = 1, 1
			case "truncated":
				raw = raw[:len(raw)-1]
			case "oversized":
				raw = append(raw, 0)
			}
			if err = os.WriteFile(info.CachePath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err = LoadCached("testdata", dir, 8, nil); err == nil {
				t.Fatal("accepted corrupt Lagrange cache")
			}
		})
	}
}

func TestCacheDoesNotBypassCanonicalChecks(t *testing.T) {
	dir, cache := t.TempDir(), t.TempDir()
	g1, g2 := files(t)
	writeFiles(t, dir, g1, g2)
	if _, _, _, err := LoadCached(dir, cache, 8, nil); err != nil {
		t.Fatal(err)
	}
	copy(g1[4*64:5*64], g1[3*64:4*64])
	writeFiles(t, dir, g1, g2)
	if _, _, _, err := LoadCached(dir, cache, 8, nil); err == nil {
		t.Fatal("cache bypassed canonical power consistency check")
	}
}

func TestConcurrentLagrangeCacheCreation(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() {
			_, _, _, err := LoadCached("testdata", dir, 8, nil)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, info, err := LoadCached("testdata", dir, 8, nil); err != nil || !info.CacheHit {
		t.Fatalf("concurrently written cache is invalid: %v", err)
	}
}

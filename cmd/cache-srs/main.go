// Command cache-srs prepares or validates the repository-local Lagrange SRS.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/aztecsrs"
)

func main() {
	domain := flag.Uint64("domain", 1<<25, "power-of-two PLONK domain")
	cache := flag.String("cache", "build/srs-cache", "Lagrange cache directory")
	crs := flag.String("crs", "", "Aztec monomial CRS directory (default AZTEC_CRS_DIR or ~/.bb-crs)")
	flag.Parse()
	start := time.Now()
	_, _, info, err := aztecsrs.LoadCached(*crs, *cache, *domain, func(s string) {
		fmt.Fprintln(os.Stderr, s)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result := struct {
		Info    aztecsrs.Info `json:"srs"`
		Seconds float64       `json:"elapsed_seconds"`
	}{info, time.Since(start).Seconds()}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

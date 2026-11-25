package ultrahonk

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

// sharedMSM uses balanced radix windows and one Horner accumulator. Every
// point operation, including table construction and doubling, uses AddUnified.
// Preconditions: BN254 Fr native field; all input points are checked on curve.
// The caller must check those points, just as before a gnark MSM call.
func sharedMSM(api frontend.API, curve *sw_emulated.Curve[sw_bn254.BaseField, sw_bn254.ScalarField], points []*sw_bn254.G1Affine, scalars []frontend.Variable, width int) (*sw_bn254.G1Affine, error) {
	if err := protocol.RequireNativeField(api); err != nil {
		return nil, err
	}
	if len(points) != len(scalars) || len(points) == 0 || width < 2 || width > 6 {
		return nil, fmt.Errorf("invalid shared MSM shape")
	}
	const scalarBits = 254
	// An extra high window flushes carry when scalarBits is divisible by width.
	windows := (scalarBits + width) / width
	half, radix := 1<<(width-1), 1<<width
	zero := emulated.ValueOf[sw_bn254.BaseField](0)
	infinity := &sw_bn254.G1Affine{X: zero, Y: zero}
	tables := make([][]*sw_bn254.G1Affine, len(points))
	negative := make([][]frontend.Variable, len(points))
	digits := make([][]frontend.Variable, len(points))
	for i := range points {
		tables[i] = make([]*sw_bn254.G1Affine, half+1)
		tables[i][0], tables[i][1] = infinity, points[i]
		for j := 2; j <= half; j++ {
			tables[i][j] = curve.AddUnified(tables[i][j-1], points[i])
		}
		bits := api.ToBinary(scalars[i], scalarBits)
		negative[i] = make([]frontend.Variable, windows)
		digits[i] = make([]frontend.Variable, windows)
		var carry frontend.Variable = 0
		for j := 0; j < windows; j++ {
			lo, hi := j*width, min((j+1)*width, scalarBits)
			var chunk frontend.Variable = 0
			if lo < scalarBits {
				chunk = api.FromBinary(bits[lo:hi]...)
			}
			t := api.Add(chunk, carry)
			// Strictly greater than half recodes negatively; a tie stays +half.
			// t <= radix, so the high bit of t+half-1 pins this predicate.
			recoded := api.ToBinary(api.Add(t, half-1), width+1)
			negative[i][j] = recoded[width]
			digits[i][j] = api.Select(negative[i][j], api.Sub(radix, t), t)
			carry = negative[i][j]
		}
		api.AssertIsEqual(carry, 0)
	}
	result := infinity
	for j := windows - 1; j >= 0; j-- {
		if j != windows-1 {
			for k := 0; k < width; k++ {
				result = curve.AddUnified(result, result)
			}
		}
		for i := range points {
			selected := curve.Mux(digits[i][j], tables[i]...)
			selected = curve.Select(negative[i][j], curve.Neg(selected), selected)
			result = curve.AddUnified(result, selected)
		}
	}
	return result, nil
}

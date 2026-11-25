package ultrahonk

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

func encodePoint(api frontend.API, base *emulated.Field[sw_bn254.BaseField], p *sw_bn254.G1Affine) []frontend.Variable {
	x, y := base.ToBitsCanonical(&p.X), base.ToBitsCanonical(&p.Y)
	return []frontend.Variable{api.FromBinary(x[:136]...), api.FromBinary(x[136:]...), api.FromBinary(y[:136]...), api.FromBinary(y[136:]...)}
}

// decodePoint constrains both the 136/118-bit representation and the canonical
// Fp coordinates. BN254 G1 has cofactor one; (0,0) denotes infinity.
func decodePoint(api frontend.API, base *emulated.Field[sw_bn254.BaseField], curve *sw_emulated.Curve[sw_bn254.BaseField, sw_bn254.ScalarField], in protocol.Point) *sw_bn254.G1Affine {
	xbits := append(api.ToBinary(in[0], 136), api.ToBinary(in[1], 118)...)
	ybits := append(api.ToBinary(in[2], 136), api.ToBinary(in[3], 118)...)
	x, y := base.FromBits(xbits...), base.FromBits(ybits...)
	base.AssertIsInRange(x)
	base.AssertIsInRange(y)
	point := &sw_bn254.G1Affine{X: *x, Y: *y}
	curve.AssertIsOnCurve(point)
	return point
}

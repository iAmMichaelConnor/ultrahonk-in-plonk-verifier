package poseidon2

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

func nativeExternal(s [4]fr.Element) [4]fr.Element {
	m := [4][4]uint64{{5, 7, 1, 3}, {4, 6, 1, 1}, {1, 3, 5, 7}, {1, 1, 4, 6}}
	var out [4]fr.Element
	for i, row := range m {
		for j, c := range row {
			var k, t fr.Element
			k.SetUint64(c)
			t.Mul(&s[j], &k)
			out[i].Add(&out[i], &t)
		}
	}
	return out
}

func nativeSbox(x fr.Element) fr.Element {
	var x2, x4 fr.Element
	x2.Square(&x)
	x4.Square(&x2)
	x4.Mul(&x4, &x)
	return x4
}

func nativePermutation(s [4]fr.Element) [4]fr.Element {
	s = nativeExternal(s)
	for r := 0; r < 64; r++ {
		if r < 4 || r >= 60 {
			for i := range s {
				var c fr.Element
				c.SetBigInt(params.C[r][i])
				s[i].Add(&s[i], &c)
				s[i] = nativeSbox(s[i])
			}
			s = nativeExternal(s)
		} else {
			var c, total fr.Element
			c.SetBigInt(params.C[r][0])
			s[0].Add(&s[0], &c)
			s[0] = nativeSbox(s[0])
			for i := range s {
				total.Add(&total, &s[i])
			}
			for i := range s {
				var d fr.Element
				d.SetBigInt(params.D[i])
				s[i].Mul(&s[i], &d).Add(&s[i], &total)
			}
		}
	}
	return s
}

// HashNative computes the same length-bound Aztec sponge as Hash. It rejects
// noncanonical inputs and is useful for publishing the digest-profile statement.
func HashNative(input []*big.Int) (*big.Int, error) {
	var s [4]fr.Element
	s[3].SetBigInt(new(big.Int).Lsh(big.NewInt(int64(len(input))), 64))
	for _, x := range input {
		if x == nil || x.Sign() < 0 || x.Cmp(protocol.ScalarModulus()) >= 0 {
			return nil, fmt.Errorf("noncanonical Poseidon2 input")
		}
	}
	blocks := (len(input) + 2) / 3
	if blocks == 0 {
		blocks = 1
	}
	for b := 0; b < blocks; b++ {
		for i := 0; i < 3 && 3*b+i < len(input); i++ {
			var x fr.Element
			x.SetBigInt(input[3*b+i])
			s[i].Add(&s[i], &x)
		}
		s = nativePermutation(s)
	}
	return s[0].BigInt(new(big.Int)), nil
}

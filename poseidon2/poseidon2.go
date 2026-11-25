// Package poseidon2 implements the Aztec v6 BN254 scalar-field sponge.
package poseidon2

import (
	_ "embed"
	"encoding/json"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

//go:embed constants.json
var parameterJSON []byte
var params struct {
	D [4]*big.Int
	C [64][4]*big.Int
}

func init() {
	var raw struct {
		D [4]string     `json:"diagonal_minus_one"`
		C [64][4]string `json:"round_constants"`
	}
	if err := json.Unmarshal(parameterJSON, &raw); err != nil {
		panic(err)
	}
	parse := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Sign() < 0 || n.Cmp(protocol.ScalarModulus()) >= 0 {
			panic("invalid Poseidon2 constant")
		}
		return n
	}
	for i, s := range raw.D {
		params.D[i] = parse(s)
	}
	for i, row := range raw.C {
		for j, s := range row {
			params.C[i][j] = parse(s)
		}
	}
}
func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	return api.Mul(api.Mul(x2, x2), x)
}
func external(api frontend.API, s [4]frontend.Variable) [4]frontend.Variable {
	// Factored form of the exact Aztec width-four matrix. This uses eight
	// additions instead of four independent four-term dot products.
	t0 := api.Add(s[0], s[1])
	t1 := api.Add(s[2], s[3])
	t2 := api.Add(api.Mul(2, s[1]), t1)
	t3 := api.Add(api.Mul(2, s[3]), t0)
	t4 := api.Add(api.Mul(4, t1), t3)
	t5 := api.Add(api.Mul(4, t0), t2)
	return [4]frontend.Variable{api.Add(t3, t5), t5, api.Add(t2, t4), t4}
}
func Permutation(api frontend.API, state [4]frontend.Variable) [4]frontend.Variable {
	if err := protocol.RequireNativeField(api); err != nil {
		panic(err)
	}
	state = external(api, state)
	for r := 0; r < 64; r++ {
		if r < 4 || r >= 60 {
			for i := range state {
				state[i] = sbox(api, api.Add(state[i], params.C[r][i]))
			}
			state = external(api, state)
		} else {
			state[0] = sbox(api, api.Add(state[0], params.C[r][0]))
			total := api.Add(state[0], state[1], state[2], state[3])
			for i := range state {
				state[i] = api.Add(total, api.Mul(state[i], params.D[i]))
			}
		}
	}
	return state
}

// Hash absorbs field elements at rate three. Input length is a circuit constant.
func Hash(api frontend.API, input []frontend.Variable) frontend.Variable {
	iv := new(big.Int).Lsh(big.NewInt(int64(len(input))), 64)
	s := [4]frontend.Variable{0, 0, 0, iv}
	blocks := (len(input) + 2) / 3
	if blocks == 0 {
		blocks = 1
	}
	for b := 0; b < blocks; b++ {
		for i := 0; i < 3 && 3*b+i < len(input); i++ {
			s[i] = api.Add(s[i], input[3*b+i])
		}
		s = Permutation(api, s)
	}
	return s[0]
}

package scalar

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/protocol"
)

const libraGeneratorHex = "07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76"

// OpeningScalars computes the Shplemini MSM scalars and checks Libra in the
// ZK flavor. The caller must validate points and use the returned scalars in
// the matching MSM and pairing. Challenges must be bound to this proof.
func OpeningScalars(api frontend.API, proof *protocol.Proof, c protocol.Challenges) ([]frontend.Variable, error) {
	if err := protocol.RequireNativeField(api); err != nil {
		return nil, err
	}
	zk := proof.ZK
	mask := 0
	if zk {
		mask = 1
	}
	eval, ec := proof.Evaluations, len(proof.Evaluations)
	claimed := proof.LibraClaimed
	negative := proof.Negative
	lib := proof.LibraEvaluations
	r, rho, nu, z := c.R, c.Rho, c.Nu, c.Z
	rp := make([]frontend.Variable, protocol.Rounds)
	rp[0] = r
	for i := 1; i < protocol.Rounds; i++ {
		rp[i] = api.Mul(rp[i-1], rp[i-1])
	}
	rhop := make([]frontend.Variable, ec)
	rhop[0] = 1
	batched := frontend.Variable(0)
	for i := range rhop {
		if i > 0 {
			rhop[i] = api.Mul(rhop[i-1], rho)
		}
		batched = api.Add(batched, api.Mul(rhop[i], eval[i]))
	}
	nup := make([]frontend.Variable, 2*protocol.Rounds+5)
	nup[0] = 1
	for i := 1; i < len(nup); i++ {
		nup[i] = api.Mul(nup[i-1], nu)
	}
	pos := make([]frontend.Variable, protocol.Rounds)
	previous := batched
	for i := protocol.Rounds - 1; i >= 0; i-- {
		u := c.U[i]
		a := api.Mul(rp[i], api.Sub(1, u))
		previous = api.Div(api.Sub(api.Mul(2, rp[i], previous), api.Mul(negative[i], api.Sub(a, u))), api.Add(a, u))
		pos[i] = previous
	}
	pscale := make([]frontend.Variable, protocol.Rounds)
	nscale := make([]frontend.Variable, protocol.Rounds)
	for i := 0; i < protocol.Rounds; i++ {
		pscale[i] = api.Div(nup[2*i], api.Sub(z, rp[i]))
		nscale[i] = api.Div(nup[2*i+1], api.Add(z, rp[i]))
	}
	unshift := api.Neg(api.Add(pscale[0], nscale[0]))
	shift := api.Div(api.Sub(nscale[0], pscale[0]), r)
	out := []frontend.Variable{1}
	count := 36 + mask
	for i := 0; i < count; i++ {
		s := api.Mul(unshift, rhop[i])
		if i >= 28+mask && i < 33+mask {
			s = api.Add(s, api.Mul(shift, rhop[count+i-(28+mask)]))
		}
		out = append(out, s)
	}
	constant := frontend.Variable(0)
	for i := 0; i < protocol.Rounds; i++ {
		constant = api.Add(constant, api.Mul(pscale[i], pos[i]), api.Mul(nscale[i], negative[i]))
		if i > 0 {
			out = append(out, api.Neg(api.Add(pscale[i], nscale[i])))
		}
	}
	if zk {
		g := mustInt(libraGeneratorHex, 16)
		points := []frontend.Variable{r, api.Mul(g, r), r, 1, r}
		groups := []frontend.Variable{0, 0, 0}
		indices := []int{0, 1, 1, 1, 2}
		values := []frontend.Variable{lib[0], lib[1], lib[2], 0, lib[3]}
		for i := 0; i < 5; i++ {
			s := api.Div(nup[2*protocol.Rounds+i], api.Sub(z, points[i]))
			groups[indices[i]] = api.Sub(groups[indices[i]], s)
			constant = api.Add(constant, api.Mul(s, values[i]))
		}
		out = append(out, groups...)
		checkLibra(api, r, lib, claimed, c)
	}
	out = append(out, constant, z)
	return out, nil
}
func mustInt(s string, base int) *big.Int {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("bad constant")
	}
	return n
}

func checkLibra(api frontend.API, r frontend.Variable, ev [4]frontend.Variable, claimed frontend.Variable, c protocol.Challenges) {
	g := mustInt(libraGeneratorHex, 16)
	gi := new(big.Int).ModInverse(g, protocol.ScalarModulus())
	pow := r
	for i := 0; i < 8; i++ {
		pow = api.Mul(pow, pow)
	}
	van := api.Sub(pow, 1)
	api.AssertIsEqual(api.Mul(van, api.Inverse(van)), 1)
	root := big.NewInt(1)
	sum := api.Inverse(api.Sub(r, 1))
	first := sum
	for i := 0; i < protocol.Rounds; i++ {
		u := c.U[i]
		up := frontend.Variable(1)
		for j := 0; j < 9; j++ {
			root.Mul(root, gi).Mod(root, protocol.ScalarModulus())
			d := api.Inverse(api.Sub(api.Mul(new(big.Int).Set(root), r), 1))
			sum = api.Add(sum, api.Mul(up, d))
			up = api.Mul(up, u)
		}
	}
	scale := api.Div(van, 256)
	f := api.Mul(sum, scale)
	l0 := api.Mul(first, scale)
	last := api.Div(scale, api.Sub(api.Mul(g, r), 1))
	lhs := api.Add(api.Mul(l0, ev[2]), api.Mul(api.Sub(r, gi), api.Sub(ev[1], ev[2], api.Mul(ev[0], f))), api.Mul(last, api.Sub(ev[2], claimed)))
	api.AssertIsEqual(lhs, api.Mul(van, ev[3]))
}

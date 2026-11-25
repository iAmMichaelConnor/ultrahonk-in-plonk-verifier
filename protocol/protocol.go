// Package protocol defines the pinned Aztec v6 Poseidon2 UltraHonk format.
package protocol

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

const (
	Rounds            = 25
	VKFields          = 115
	VKPoints          = 28
	AccumulatorFields = 8
	PublicOffset      = 5
	MaxPublicInputs   = 1 << 20
)

// ScalarModulus returns a fresh value. Callers cannot mutate protocol constants.
func ScalarModulus() *big.Int { return fr.Modulus() }

// RequireNativeField rejects arithmetic in a field different from the protocol's Fr.
func RequireNativeField(api frontend.API) error {
	if api.Compiler().Field().Cmp(ScalarModulus()) != 0 {
		return fmt.Errorf("UltraHonk requires the BN254 scalar field")
	}
	return nil
}

func ProofFields(zk bool) int {
	if zk {
		return 458
	}
	return 410
}
func RoundSize(zk bool) int {
	if zk {
		return 9
	}
	return 8
}
func EntityCount(zk bool) int {
	if zk {
		return 42
	}
	return 41
}

// Challenges are full-width Fr values, except the separate accumulator separator.
type Challenges struct {
	Eta, RomLogupGamma, Beta, Gamma, Alpha, Gate, Libra frontend.Variable
	U                                                   [Rounds]frontend.Variable
	Rho, R, Nu, Z                                       frontend.Variable
}

// Ordered returns challenges in transcript order, for reference-vector checks.
func (c Challenges) Ordered(zk bool) []frontend.Variable {
	out := []frontend.Variable{c.Eta, c.RomLogupGamma, c.Beta, c.Gamma, c.Alpha, c.Gate}
	if zk {
		out = append(out, c.Libra)
	}
	out = append(out, c.U[:]...)
	return append(out, c.Rho, c.R, c.Nu, c.Z)
}

type Point [4]frontend.Variable

// Span identifies fields in the complete sequence, including application inputs.
type Span struct{ Start, Length int }

func (s Span) Slice(fields []frontend.Variable) []frontend.Variable {
	return fields[s.Start : s.Start+s.Length]
}

// Layout is the only definition of the serialized field order.
type Layout struct {
	ZK                                                          bool
	Public, Mask, WL, WR, WO, Counts, Tags, W4, Inverses, ZPerm Span
	Concat, LibraSum                                            Span
	Univariates                                                 [Rounds]Span
	Evaluations, LibraClaimed, Grand, Quot                      Span
	Folds                                                       [Rounds - 1]Span
	Negative, LibraEvaluations, Q, W                            Span
	Fields                                                      int
}

func NewLayout(publicCount int, zk bool) (Layout, error) {
	l := Layout{ZK: zk}
	if publicCount < AccumulatorFields || publicCount > MaxPublicInputs {
		return l, fmt.Errorf("unsupported public-input count")
	}
	next := func(n int) Span { s := Span{l.Fields, n}; l.Fields += n; return s }
	l.Public = next(publicCount)
	if zk {
		l.Mask = next(4)
	}
	l.WL = next(4)
	l.WR = next(4)
	l.WO = next(4)
	l.Counts = next(4)
	l.Tags = next(4)
	l.W4 = next(4)
	l.Inverses = next(4)
	l.ZPerm = next(4)
	if zk {
		l.Concat = next(4)
		l.LibraSum = next(1)
	}
	for i := range l.Univariates {
		l.Univariates[i] = next(RoundSize(zk))
	}
	l.Evaluations = next(EntityCount(zk))
	if zk {
		l.LibraClaimed = next(1)
		l.Grand = next(4)
		l.Quot = next(4)
	}
	for i := range l.Folds {
		l.Folds[i] = next(4)
	}
	l.Negative = next(Rounds)
	if zk {
		l.LibraEvaluations = next(4)
	}
	l.Q = next(4)
	l.W = next(4)
	return l, nil
}

// Proof contains views of the same constrained fields, never copied witnesses.
type Proof struct {
	ZK                                                  bool
	Public                                              []frontend.Variable
	Mask, WL, WR, WO, Counts, Tags, W4, Inverses, ZPerm Point
	Concat                                              Point
	LibraSum                                            frontend.Variable
	Univariates                                         [Rounds][]frontend.Variable
	Evaluations                                         []frontend.Variable
	LibraClaimed                                        frontend.Variable
	Grand, Quot                                         Point
	Folds                                               [Rounds - 1]Point
	Negative                                            [Rounds]frontend.Variable
	LibraEvaluations                                    [4]frontend.Variable
	Q, W                                                Point
}

func Parse(fields []frontend.Variable, publicCount int, zk bool) (*Proof, error) {
	l, err := NewLayout(publicCount, zk)
	if err != nil {
		return nil, err
	}
	if len(fields) != l.Fields {
		return nil, fmt.Errorf("expected %d complete proof fields, got %d", l.Fields, len(fields))
	}
	point := func(s Span) Point { return Point(s.Slice(fields)) }
	p := &Proof{ZK: zk, Public: l.Public.Slice(fields), WL: point(l.WL), WR: point(l.WR), WO: point(l.WO), Counts: point(l.Counts), Tags: point(l.Tags), W4: point(l.W4), Inverses: point(l.Inverses), ZPerm: point(l.ZPerm), Evaluations: l.Evaluations.Slice(fields), Q: point(l.Q), W: point(l.W)}
	for i, s := range l.Univariates {
		p.Univariates[i] = s.Slice(fields)
	}
	for i, s := range l.Folds {
		p.Folds[i] = point(s)
	}
	copy(p.Negative[:], l.Negative.Slice(fields))
	if zk {
		p.Mask = point(l.Mask)
		p.Concat = point(l.Concat)
		p.LibraSum = fields[l.LibraSum.Start]
		p.LibraClaimed = fields[l.LibraClaimed.Start]
		p.Grand = point(l.Grand)
		p.Quot = point(l.Quot)
		copy(p.LibraEvaluations[:], l.LibraEvaluations.Slice(fields))
	}
	return p, nil
}

func (p *Proof) Accumulator() []frontend.Variable { return p.Public[len(p.Public)-AccumulatorFields:] }

// MSMPoints returns precisely the ordering used by scalar.OpeningScalars.
func (p *Proof) MSMPoints(vk []frontend.Variable) []Point {
	points := []Point{p.Q}
	if p.ZK {
		points = append(points, p.Mask)
	}
	for i := 0; i < VKPoints; i++ {
		points = append(points, Point(vk[3+4*i:7+4*i]))
	}
	points = append(points, p.WL, p.WR, p.WO, p.W4, p.ZPerm, p.Inverses, p.Counts, p.Tags)
	points = append(points, p.Folds[:]...)
	if p.ZK {
		points = append(points, p.Concat, p.Grand, p.Quot)
	}
	return append(points, Point{1, 0, 2, 0}, p.W)
}

package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark/frontend"
)

func TestModulusReturnsCopy(t *testing.T) {
	a := ScalarModulus()
	original := a.String()
	a.SetInt64(1)
	if ScalarModulus().String() != original {
		t.Fatal("mutated protocol modulus")
	}
}

func TestLayoutMatchesReferenceEvents(t *testing.T) {
	for _, tc := range []struct {
		name string
		zk   bool
	}{{"square-non-zk", false}, {"square-zk", true}} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile("../testdata/" + tc.name + "/trace.json")
			if err != nil {
				t.Fatal(err)
			}
			var tr struct {
				Events []struct {
					Kind, Name string
					Offset     int `json:"offset,string"`
					Length     int `json:"length,string"`
				}
				Proof []string
			}
			if err = json.Unmarshal(raw, &tr); err != nil {
				t.Fatal(err)
			}
			l, err := NewLayout(9, tc.zk)
			if err != nil {
				t.Fatal(err)
			}
			spans := map[string]Span{"public_inputs": l.Public, "gemini_mask": l.Mask, "w_l": l.WL, "w_r": l.WR, "w_o": l.WO, "lookup_read_counts": l.Counts, "lookup_read_tags": l.Tags, "w_4": l.W4, "lookup_inverses": l.Inverses, "z_perm": l.ZPerm, "libra_concatenation": l.Concat, "libra_sum": l.LibraSum, "evaluations": l.Evaluations, "libra_claimed_evaluation": l.LibraClaimed, "libra_grand_sum": l.Grand, "libra_quotient": l.Quot, "gemini_evaluations": l.Negative, "libra_evaluations": l.LibraEvaluations, "shplonk_q": l.Q, "kzg_w": l.W}
			for i, s := range l.Univariates {
				spans[fmt.Sprintf("sumcheck_%d", i)] = s
			}
			for i, s := range l.Folds {
				spans[fmt.Sprintf("fold_%d", i+1)] = s
			}
			for _, event := range tr.Events {
				if event.Kind != "read" {
					continue
				}
				s, ok := spans[event.Name]
				if !ok || s.Start != event.Offset || s.Length != event.Length {
					t.Fatalf("%s: span %+v differs from reference", event.Name, s)
				}
			}
			if l.Fields != len(tr.Proof) || l.Fields != ProofFields(tc.zk)+1 {
				t.Fatal("incorrect complete proof length")
			}
			if _, err = Parse(make([]frontend.Variable, l.Fields-1), 9, tc.zk); err == nil {
				t.Fatal("accepted truncated proof")
			}
		})
	}
}

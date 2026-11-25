.PHONY: check test test-short test-full test-ci test-plonk timings timings-aztec
.DEFAULT_GOAL := test

check:
	python3 -m unittest discover -s scripts -p 'test_*.py'
	python3 scripts/generate_relations.py --check
	go run ./examples/root-rollup
	go vet ./...

test: check
	go test ./... -count=1 -timeout 30m

test-short: check
	go test ./... -short -count=1

test-full: check
	FULL_VERIFIER_TEST=1 FULL_NEGATIVE_TEST=1 go test ./... -count=1 -timeout 60m

test-ci: check
	FULL_VERIFIER_TEST=1 FULL_NEGATIVE_TEST=engine go test ./... -count=1 -timeout 60m

test-plonk:
	FULL_PLONK_TEST=1 go test ./ultrahonk -run '^TestVerifierPLONKConstraints$$' -count=1 -v -timeout 30m

timings:
	FULL_PROOF_TEST=1 go test ./ultrahonk -run '^TestProverTimings$$' -count=1 -v -timeout 6h

timings-aztec:
	FULL_PROOF_TEST=1 go test ./ultrahonk -run '^TestDeferredCeremonyProver$$' -count=1 -v -timeout 6h

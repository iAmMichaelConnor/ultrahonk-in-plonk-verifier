# UltraHonk in gnark PLONK

Experimental fixed-key verifier for Aztec UltraHonk inside a BN254 gnark PLONK
circuit. The circuit checks the Poseidon2 transcript, sumcheck and all 31
batched relations, Gemini/Shplonk openings, the ZK Libra check, and the
recursive accumulator and final pairing. Each circuit binds one authenticated
verification key and proof flavour at compilation.

It supports the 410-field UltraFlavor and 458-field UltraZKFlavor Poseidon2
`DefaultIO` proof formats from
[Barretenberg 6.0.0](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0),
commit `0219f11d8133970df3974fe5ae65e006bf8c193a`. Keccak, Chonk, and targets
carrying an extra IPA claim are outside the supported format. Dependencies
are pinned to gnark v0.16.4 and the versions in [go.mod](go.mod).

## Quick tests

Use Go 1.26.10, Python 3, and Make. Start here for routine development.

```sh
make test-short
```

The quick suite verifies generated relations, checks the transcript, parser,
arithmetic and ceremony import, and verifies a retained root-rollup PLONK
proof, its expected public-input digest, and the separate final pairing. Go
builds the test and example binaries. A full
UltraHonk verifier circuit and a local ceremony cache are unnecessary for
these checks.

To verify just the retained proof, run `go run ./examples/root-rollup` from the
repo root. Its small proof, key and public witness are under
[`testdata/root-rollup/outer-proof/`](testdata/root-rollup/outer-proof/).

The [square example](examples/square/main.go) checks a retained UltraHonk
witness in gnark's test engine without compiling the circuit.

```sh
go run ./examples/square
```

## Compile and test

```sh
make test         # Routine full-verifier tests using gnark's test engine
make test-ci      # Also test recursive fixtures and adversarial mutations
make test-plonk   # Compile and solve the full verifier with the PLONK builder
make test-full    # Run extensive regressions against compiled constraints
```

Branch pushes and pull requests run the quick tests. The **PLONK tests**
workflow also offers the extended test-engine gate on demand, and version tags
run that gate before drafting a release.

### Prove a square fixture

Full proving needs Aztec's raw BN254 `bn254_g1.dat` and `bn254_g2.dat`.
Use an existing raw Barretenberg cache, or download the powers for a
`2^24` domain from the host used by the
[pinned Aztec CRS bootstrap](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/crs/bootstrap.sh).
The G1 prefix takes just over 1 GiB.

```sh
mkdir -p build/crs
curl -fL -r 0-1073742015 https://crs.aztec-cdn.foundation/g1.dat -o build/crs/bn254_g1.dat
curl -fL https://crs.aztec-cdn.foundation/g2.dat -o build/crs/bn254_g2.dat
AZTEC_CRS_DIR="$PWD/build/crs" go run ./examples/square -prove
```

The example compiles the verifier, imports the authenticated ceremony, derives
the Lagrange basis, performs PLONK setup, and proves and verifies the fixture.
The reusable Lagrange cache in `build/srs-cache/` is about 1 GiB for this domain. The
loader validates canonical points and every consecutive power, and
authenticates the Lagrange cache on each load. Set `AZTEC_CRS_DIR` to use a
different location. The default is `~/.bb-crs`.

## Circuit profiles

To use the library from your Go module, run
`go get github.com/iAmMichaelConnor/ultrahonk-in-plonk-verifier/ultrahonk`.

Use `ultrahonk.NewCircuit(vkFields, zk, options...)` with the fixed inner key,
then `shape.Assignment(appInputs, proofFields)` with the witness. The proof
array starts with its eight accumulator fields. The application input array
excludes them.

| Option | Effect |
| --- | --- |
| Default | Publish application inputs and verify the final pairing in-circuit. |
| `WithZeroAccumulator()` | Require all eight embedded accumulator fields to be zero. |
| `WithPublicInputHash()` | Publish the length-bound Poseidon2 digest of application inputs. |
| `WithDeferredPairing()` | Publish the final two G1 points for an external pairing check. |

The options compose. The deferred profile uses
`AssignmentWithDeferredPairing(appInputs, proofFields, finalPairingLimbs)`.
It publishes each point as `x.low, x.high, y.low, y.high` with 136/118-bit
limbs. The caller must authenticate the outer key and the expected application
statement and verify `e(U, Q) · e(V, [tau]Q) = 1` with the pinned Aztec G2
points. The retained proof example runs both checks independently. The
in-circuit MSM uses complete point additions for variable points. The
recursive merge uses gnark's checked GLV+fake-GLV path.

## Recorded benchmarks

The root-rollup fixtures use 113 application inputs, a nonzero recursive
accumulator, and test checkpoint children under a synthetic key tree.
Measurements are single observations on a shared AMD EPYC host using the
Aztec ceremony. The PLONK prover time includes a fresh witness solve.

| Root-rollup circuit, hashed inputs | Constraints | Witness solve | PLONK prove |
| --- | ---: | ---: | ---: |
| Pairing in circuit | 15,424,060 | — | — |
| Deferred pairing | 13,840,170 | 1.94 s | 67.75 s |
| Deferred pairing, earlier MSM | 19,318,674 | 3.33 s | 121.25 s |

The current deferred run took 18.22 s to compile and 36.63 s for setup. These
times are separate from the prover time. See the
[measurement and source fingerprint](testdata/root-rollup/outer-proof/measurement.json).

## Releases and provenance

Pushing a version tag runs the extended tests and creates a GitHub draft with
generated release notes. Review the notes and publish the draft on GitHub.
Keep ceremony material, keys, generated circuits, and timing outputs in
ignored `build/` or a separate local directory.

Original Aztec Solidity relations, generated reference expressions, and
source pins live under [reference/aztec](reference/aztec). Experimental and
unaudited. Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

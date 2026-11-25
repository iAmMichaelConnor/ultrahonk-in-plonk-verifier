#!/usr/bin/env python3
"""Lower the pinned Circom SSA to gnark. Reject all unsupported syntax."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
INPUTS = {"eta", "romLogupGamma", "beta", "gamma", "publicInputsDelta", "domainSep", "alpha"}
DECLARATIONS = [
    "pragma circom 2.2.3;",
    "template UltraRelations() {",
    "signal input p[41];",
    "signal input eta, romLogupGamma, beta, gamma, publicInputsDelta, domainSep, alpha;",
    "signal output evaluations[31];",
    "signal output batched;",
]


def lower(source):
    """Parse the complete supported template; comments are non-semantic."""
    lines = [
        "// Code generated from reference/aztec/relations.circom; DO NOT EDIT.",
        "// Copyright 2024 Aztec Labs. SPDX-License-Identifier: Apache-2.0",
        "package scalar", "", 'import "github.com/consensys/gnark/frontend"', "",
        "func Relations(api frontend.API, p [41]frontend.Variable, eta, romLogupGamma, beta, gamma, publicInputsDelta, domainSep, alpha frontend.Variable) frontend.Variable {",
    ]
    declarations = 0
    nodes = 0
    evaluations = set()
    batched = False
    closed = False

    def term(value):
        if value in INPUTS:
            return value
        if re.fullmatch(r"p\[(?:[0-9]|[1-3][0-9]|40)\]", value):
            return value
        if re.fullmatch(r"t(?:0|[1-9][0-9]*)", value) and int(value[1:]) < nodes:
            return value
        if re.fullmatch(r"0|[1-9][0-9]*", value) and int(value) < MODULUS:
            return '"' + value + '"' if len(value) > 15 else value
        raise ValueError("unknown or forward-referenced operand: " + value)

    for number, raw in enumerate(source.splitlines(), 1):
        text = raw.partition("//")[0].strip()
        if not text:
            continue
        if closed:
            raise ValueError(f"line {number}: input after template end")
        if declarations < len(DECLARATIONS):
            if text != DECLARATIONS[declarations]:
                raise ValueError(f"line {number}: unexpected declaration: {text}")
            declarations += 1
            continue
        match = re.fullmatch(r"signal (t\d+); \1 <== (\S+) ([+*\-]) (\S+);", text)
        if match and not batched:
            name, a, op, b = match.groups()
            if name != f"t{nodes}":
                raise ValueError(f"line {number}: unexpected node {name}")
            a, b = term(a), term(b)
            nodes += 1
            method = {"+": "Add", "-": "Sub", "*": "Mul"}[op]
            lines.append(f"\t{name} := api.{method}({a}, {b})")
            continue
        match = re.fullmatch(r"evaluations\[(\d+)\] <== (\S+);", text)
        if match and not batched:
            index, value = match.groups()
            index = int(index)
            if not 0 <= index < 31 or index in evaluations:
                raise ValueError(f"line {number}: duplicate or invalid evaluation")
            term(value)
            evaluations.add(index)
            continue
        if text == "batched <== t463;" and not batched and nodes == 464 and len(evaluations) == 31:
            batched = True
            continue
        if text == "}" and batched:
            closed = True
            continue
        raise ValueError(f"line {number}: unsupported statement: {text}")
    if not closed or not batched or nodes != 464:
        raise ValueError("incomplete relation template")
    return "\n".join(lines + ["\treturn t463", "}", ""])


def generate(root=ROOT, check=False):
    refs = root / "reference/aztec"
    manifest = json.loads((refs / "sources.json").read_text())
    required = {"Relations.sol", "HonkTypes.sol", "relations.circom"}
    if set(manifest["sha256"]) != required:
        raise ValueError("unexpected source manifest")
    for name in sorted(required):
        if hashlib.sha256((refs / name).read_bytes()).hexdigest() != manifest["sha256"][name]:
            raise ValueError("source hash mismatch: " + name)
    output = lower((refs / "relations.circom").read_text())
    target = root / "scalar/relations_generated.go"
    if check:
        if target.read_text() != output:
            raise ValueError("generated relations are stale")
    else:
        target.write_text(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check reproducibility without writing")
    args = parser.parse_args()
    generate(check=args.check)

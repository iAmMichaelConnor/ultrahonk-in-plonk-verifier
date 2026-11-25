import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("generate_relations", ROOT / "scripts/generate_relations.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / "reference/aztec/relations.circom").read_text()

    def test_reproducible(self):
        gen.generate(check=True)

    def test_rejects_unknown_semantics(self):
        for statement in ["t463 === 0;", "assert(0 == 1);", "signal extra;", "batched <== 0;", "t0 <-- 0;"]:
            with self.subTest(statement=statement), self.assertRaises(ValueError):
                gen.lower(self.source.replace("\n}", "\n    " + statement + "\n}"))

    def test_rejects_invalid_operands_and_shape(self):
        for old, new in [("p[21] - 3", "p[41] - 3"), ("p[21] - 3", "t1 - 3"),
                         ("evaluations[0]", "evaluations[1]"), ("t463;", "t462;"),
                         ("signal input p[41];", "signal input p[42];")]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                gen.lower(self.source.replace(old, new, 1))

    def test_rejects_changed_pin_without_overwriting_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "reference", root / "reference")
            (root / "scalar").mkdir()
            target = root / "scalar/relations_generated.go"
            target.write_text("untouched")
            with (root / "reference/aztec/Relations.sol").open("a") as f:
                f.write("\n// modified\n")
            with self.assertRaises(ValueError):
                gen.generate(root)
            self.assertEqual(target.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()

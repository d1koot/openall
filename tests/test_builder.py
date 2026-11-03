"""Smoke tests for the shelf builder on a synthetic PE (no compiler needed). Needs: pip install capstone pefile"""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
try:
    import capstone, pefile  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False


@unittest.skipUnless(HAVE, "capstone/pefile not installed")
class BuilderTests(unittest.TestCase):
    def run_py(self, *args, env=None):
        e = dict(os.environ); e.update(env or {})
        return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, env=e, cwd=ROOT)

    def test_builder_on_synthetic_pe(self):
        with tempfile.TemporaryDirectory() as d:
            exe = Path(d) / "sample.exe"
            self.assertEqual(self.run_py(ROOT / "tests/make_sample_pe.py", exe).returncode, 0)
            out = Path(d) / "shelves"
            r = self.run_py(ROOT / "scripts/build_shelves.py", exe, "--out", out, env={"OPENALL_REFSETS": str(Path(d) / "rs")})
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in ("shelf0_container.json", "shelf1_code.jsonl", "shelf2_data.jsonl", "bottom_up.json", "SUMMARY.md"):
                self.assertTrue((out / name).exists(), name)
            json.loads((out / "shelf0_container.json").read_text())
            for line in open(out / "shelf1_code.jsonl"):
                self.assertTrue(json.loads(line)["id"].startswith("F:"))
            # the whole shelf-3 chain works on it: stubs, status, a refusing book
            sh = ROOT / "scripts/shelf3.py"
            self.assertEqual(self.run_py(sh, "stubs", "--shelves", out).returncode, 0)
            self.assertEqual(self.run_py(sh, "status", "--shelves", out).returncode, 0)

    def test_non_pe_x64_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            junk = Path(d) / "x.exe"; junk.write_bytes(b"MZ" + b"\0" * 200)
            r = self.run_py(ROOT / "scripts/build_shelves.py", junk, "--out", Path(d) / "o")
            self.assertNotEqual(r.returncode, 0)

    def test_stale_reference_set_is_reported_and_not_used(self):
        with tempfile.TemporaryDirectory() as d:
            exe = Path(d) / "sample.exe"; self.run_py(ROOT / "tests/make_sample_pe.py", exe)
            env = {"OPENALL_REFSETS": str(Path(d) / "rs")}
            self.assertEqual(self.run_py(ROOT / "scripts/build_shelves.py", "--learn", exe, env=env).returncode, 0)
            rs = next((Path(d) / "rs").glob("*.json"))
            data = json.loads(rs.read_text()); data["analysis_version"] = 0; rs.write_text(json.dumps(data))
            r = self.run_py(ROOT / "scripts/build_shelves.py", exe, "--out", Path(d) / "o", env=env)
            self.assertIn("STALE", r.stdout)


if __name__ == "__main__":
    unittest.main()

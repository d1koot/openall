"""Unit tests for the shelf-3 checker and task ordering. No compiler, no binaries needed.
Run:  python3 tests/run_tests.py
"""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import shelf3  # noqa: E402


def fn(fid, **kw):
    r = dict(id=fid, source="pdata", size=10, insn_count=5, blocks=1, callers=[], callees=[], imports=[], strings=[],
             data_read=[], data_written=[], address_taken_fns=[], in_tables=[], uses_tables=[], landing_pad_of=[],
             landing_pads=[], indirect_calls=0, indirect_jumps=0, jump_tables=0, name_hint=None, name_source="none",
             origin="unknown", origin_why="test", thunk_to=None, disasm=None)
    r.update(kw)
    return r


def make_shelves(root, funcs, strings=(), groups=None, imports=None):
    root.mkdir(parents=True, exist_ok=True)
    (root / "disasm").mkdir(exist_ok=True)
    with open(root / "shelf1_code.jsonl", "w") as fh:
        for f in funcs:
            f["disasm"] = f"disasm/{f['id'][2:]}.txt"
            (root / f["disasm"]).write_text("00000000  ret\n")
            fh.write(json.dumps(f) + "\n")
    with open(root / "shelf0_strings.jsonl", "w") as fh:
        for sid, text in strings:
            fh.write(json.dumps(dict(id=sid, text=text, used_by=[])) + "\n")
    (root / "shelf2_data.jsonl").write_text("")
    (root / "shelf0_container.json").write_text(json.dumps(dict(
        imports=imports or {}, sections=[dict(id="X:.text")])))
    groups = groups or [[f["id"]] for f in funcs]
    (root / "bottom_up.json").write_text(json.dumps(groups))
    return shelf3.Shelves(root)


def page(fid, evidence, conf="medium", children="", extra=""):
    return (f"# {fid}\ntitle: t\nsummary: s [I]\ninputs: -\neffects: -\nevidence:\n" + "\n".join(f"- {e}" for e in evidence) +
            f"\nconfidence: {conf}\nchildren_read: {children}\nopen_questions: -\n{extra}")


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name) / "s"
        self.sh = make_shelves(root, [
            fn("F:00001000", callees=["F:00002000"], strings=["S:00005000"], imports=["I:k.dll!Foo"]),
            fn("F:00002000", callers=["F:00001000"], origin="runtime"),
            fn("F:00003000", strings=["S:00006000"]),
        ], strings=[("S:00005000", "hello"), ("S:00006000", "other")], imports={"k.dll": ["Foo"]})
        (self.sh.pages / "F-00002000.md").write_text(
            "# F:00002000\ngenerated: stub\norigin: runtime\nsummary: runtime [O]\nevidence:\n- x [O] refs: F:00002000\n")

    def tearDown(self): self.tmp.cleanup()

    def errors(self, text, fid="F:00001000"):
        p = self.sh.pages / f"F-{fid[2:]}.md"
        p.write_text(text)
        return shelf3.check_page(self.sh, p)

    def test_good_page_passes(self):
        t = page("F:00001000", ["It prints a greeting. [O] refs: S:00005000", "It calls the helper. [O] refs: F:00002000"],
                 children="F:00002000")
        self.assertEqual(self.errors(t), [])

    def test_observed_claim_needs_refs(self):
        t = page("F:00001000", ["It opens a socket. [O]"], children="F:00002000")
        self.assertTrue(any("without refs" in e for e in self.errors(t)))

    def test_unknown_ref_is_rejected(self):
        t = page("F:00001000", ["Something. [I] refs: F:deadbeef"], children="F:00002000")
        self.assertTrue(any("does not exist" in e for e in self.errors(t)))

    def test_foreign_string_is_rejected(self):
        t = page("F:00001000", ["Something. [O] refs: S:00006000"], children="F:00002000")   # belongs to F:00003000
        self.assertTrue(any("not connected" in e for e in self.errors(t)))

    def test_high_confidence_needs_two_grounded_bullets(self):
        t = page("F:00001000", ["One. [O] refs: S:00005000"], conf="high", children="F:00002000")
        self.assertTrue(any("two angles" in e for e in self.errors(t)))

    def test_children_read_must_list_callees(self):
        t = page("F:00001000", ["One. [O] refs: S:00005000"], children="")
        self.assertTrue(any("children_read" in e for e in self.errors(t)))

    def test_real_secret_is_flagged_but_mangled_names_are_not(self):
        bad = page("F:00001000", ["One. [O] refs: S:00005000"], children="F:00002000", extra="note: password=hunter2\n")
        self.assertTrue(any("secret" in e for e in self.errors(bad)))
        mangled = page("F:00001000", ["Calls _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKcxxxxxxxxxxxx. [O] refs: S:00005000"],
                       children="F:00002000")
        self.assertEqual(self.errors(mangled), [])

    def test_missing_label_is_rejected(self):
        t = page("F:00001000", ["No label here refs: S:00005000"], children="F:00002000")
        self.assertTrue(any("no label" in e for e in self.errors(t)))

    def test_book_is_refused_while_check_fails(self):
        class A: batch = 1; max_insns = 250
        self.assertEqual(shelf3.cmd_book(self.sh, A()), 1)


class OrderTests(unittest.TestCase):
    def test_recursion_does_not_block_and_batches_are_independent(self):
        with tempfile.TemporaryDirectory() as d:
            sh = make_shelves(Path(d) / "s", [
                fn("F:00000010", callees=["F:00000010"]),                       # calls itself
                fn("F:00000020", callees=["F:00000030"]), fn("F:00000030", callees=["F:00000020"]),   # mutual recursion
                fn("F:00000040", callees=["F:00000010"]),                       # depends on the first
                fn("F:00000050"),                                               # independent leaf
            ], groups=[["F:00000010"], ["F:00000020", "F:00000030"], ["F:00000040"], ["F:00000050"]])
            first = shelf3.ready_tasks(sh, 8, 1000)
            self.assertIn("F:00000010", first)                                  # self-call is not a deadlock
            self.assertIn("F:00000050", first)
            self.assertNotIn("F:00000040", first)                               # its callee has no page yet
            self.assertTrue({"F:00000020", "F:00000030"} <= set(first))         # a cycle is allowed together


if __name__ == "__main__":
    unittest.main()

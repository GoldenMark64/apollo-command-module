import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from apollo_source import analyze_c_function


class SourceFunctionEvidenceTests(unittest.TestCase):
    def test_assignment_return_and_control_evidence(self):
        source = """Thing *prototype(int ok);

Thing *build_thing(int ok)
{
    Thing *model = NULL;
    if (ok)
    {
        model = allocate();
    }
    else
    {
        model = fallback();
    }
    return model;
}
"""
        out = analyze_c_function(source, "build_thing", ["model"])
        self.assertEqual([a["target"] for a in out["assignments"]], ["model", "model", "model"])
        self.assertEqual(out["assignments"][0]["enclosing_braced_controls"], [])
        self.assertEqual(out["assignments"][1]["enclosing_braced_controls"], ["if (ok)"])
        self.assertEqual(out["assignments"][2]["enclosing_braced_controls"], ["else"])
        self.assertEqual(out["returns"][0]["expression"], "model")

    def test_comments_strings_calls_and_prototypes_do_not_define_function(self):
        source = r"""// fake(int x) { return x; }
const char *s = "fake(int x) { return x; }";
int fake(int x);
int real(int x)
{
    return x;
}
"""
        with self.assertRaisesRegex(ValueError, "function definition not found"):
            analyze_c_function(source, "fake")
        self.assertEqual(analyze_c_function(source, "real")["returns"][0]["expression"], "x")

    def test_ambiguous_definitions_are_rejected(self):
        source = "int f(void) { return 1; }\nint f(void) { return 2; }\n"
        with self.assertRaisesRegex(ValueError, "ambiguous function definition"):
            analyze_c_function(source, "f")

    def test_variable_filter_does_not_misreport_member_assignment(self):
        source = """int f(void)
{
    int model = 0;
    int other = 1;
    obj->model = other;
    model += other;
    return model;
}
"""
        out = analyze_c_function(source, "f", ["model"])
        self.assertEqual([(a["target"], a["operator"]) for a in out["assignments"]],
                         [("model", "="), ("model", "+=")])

    def test_cli_wrapper(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.c"
            path.write_text("""int build(int ok)
{
    int model = 0;
    if (ok) {
        model = 1;
    }
    return model;
}
""", encoding="utf-8")
            proc = subprocess.run([
                sys.executable, str(repo / "apollo.py"), "--json", "source", "function",
                "--file", str(path), "--symbol", "build", "--variable", "model",
            ], cwd=repo, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(proc.stdout)
            self.assertEqual(data["operation"], "source.function")
            self.assertEqual(data["outputs"]["symbol"], "build")
            self.assertEqual(data["outputs"]["returns"][0]["expression"], "model")
            self.assertEqual(len(data["outputs"]["assignments"]), 2)


if __name__ == "__main__":
    unittest.main()

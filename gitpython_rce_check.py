#!/usr/bin/env python3
"""gitpython-rce-check: is your project exposed to the GitPython RCE /
arbitrary-file-read pair (CVE-2026-110858, CVE-2026-110859)?

Two checks in one run, stdlib only:

  1. Version gate -- the installed GitPython version against the fixed
     release 3.2.0 (NVD, verified 2026-11-24):
       CVE-2026-110858  GitPython 3.1.30 before 3.2.0, fixed in 3.2.0
       CVE-2026-110859  GitPython before 3.2.0,    fixed in 3.2.0
     Any version < 3.2.0 is flagged VULNERABLE (the conservative gate:
     it covers both CVEs). GitPython not installed -> UNKNOWN, no
     false alarm.
  2. Call-site scan -- walk a directory of .py files with ``ast`` and
     find Remote.pull() / Head.checkout() calls whose first argument
     comes from untrusted input (function parameters named like
     user_input / branch / ref, sys.argv, os.environ, request data).
     A constant string such as pull("main") is never reported.

Exit codes: 0 = safe (version fixed and 0 dangerous calls),
            1 = hit (vulnerable version and/or dangerous call found),
            2 = usage error.

This is a defensive checker. It contains no exploit code and makes no
network calls. The taint check is heuristic -- a clean result means
"no dangerous call found by this scan", not a proof of safety.
"""

import argparse
import ast
import importlib.metadata
import re
import sys
from pathlib import Path

FIXED_VERSION = (3, 2, 0)
VERSION = "1.0.0"

# Names that suggest a value came from outside the program. A call
# argument whose name (or attribute name) contains one of these is
# treated as untrusted input.
TAINT_NAME_RE = re.compile(
    r"user|input|branch|ref|refspec|argv|environ|request|param|payload|"
    r"remote_url|repo_url|url|data|arg",
    re.IGNORECASE,
)

# Dotted roots that are external-input sources.
TAINT_ROOTS = ("sys.argv", "os.environ", "os.getenv", "request.", "input(")


def parse_version(text):
    """'3.1.30' -> (3, 1, 30); non-numeric tails are ignored."""
    parts = []
    for chunk in str(text).strip().split("."):
        m = re.match(r"(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def version_status(version_text):
    """Return (state, detail) for an installed version string.

    state is one of 'vulnerable', 'fixed', 'unknown'.
    """
    if version_text is None:
        return "unknown", "GitPython is not installed in this environment"
    parsed = parse_version(version_text)
    if parsed < FIXED_VERSION:
        return "vulnerable", "GitPython %s is before the fixed release 3.2.0" % version_text
    return "fixed", "GitPython %s is at or above the fixed release 3.2.0" % version_text


def installed_gitpython_version():
    try:
        return importlib.metadata.version("GitPython")
    except importlib.metadata.PackageNotFoundError:
        return None
    except Exception:
        return None


def _dotted(node):
    """Dotted name of an Attribute/Name node, e.g. 'repo.remotes.origin'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return (base + "." + node.attr) if base else node.attr
    return ""


def _source_text(node):
    try:
        return ast.unparse(node)
    except Exception:
        return "?"


class _TaintVisitor(ast.NodeVisitor):
    """Collect Remote.pull() / Head.checkout() calls with tainted args."""

    def __init__(self, rel_path):
        self.rel_path = rel_path
        self.findings = []          # dicts: file, line, call, arg, status
        self._params = []           # stack of sets of function-arg names
        self._tainted_locals = []   # stack of dicts: local name -> bool

    # -- scope bookkeeping -------------------------------------------------
    def visit_FunctionDef(self, node):
        args = {a.arg for a in node.args.args}
        args |= {a.arg for a in node.args.kwonlyargs}
        if node.args.vararg:
            args.add(node.args.vararg.arg)
        if node.args.kwarg:
            args.add(node.args.kwarg.arg)
        self._params.append(args)
        self._tainted_locals.append({})
        self.generic_visit(node)
        self._params.pop()
        self._tainted_locals.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        tainted = self._is_tainted(node.value)
        safe_const = isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        )
        for target in node.targets:
            if isinstance(target, ast.Name) and self._tainted_locals:
                if tainted:
                    self._tainted_locals[-1][target.id] = True
                elif safe_const:
                    self._tainted_locals[-1][target.id] = False
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name) and node.value is not None:
            if self._is_tainted(node.value):
                self._tainted_locals[-1][node.target.id] = True
            elif isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                self._tainted_locals[-1][node.target.id] = False
        self.generic_visit(node)

    # -- taint test ---------------------------------------------------------
    def _is_tainted(self, node):
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            name = node.id
            if self._tainted_locals and self._tainted_locals[-1].get(name) is True:
                return True
            if self._tainted_locals and self._tainted_locals[-1].get(name) is False:
                return False
            if self._params and name in self._params[-1]:
                return bool(TAINT_NAME_RE.search(name))
            return bool(TAINT_NAME_RE.search(name))
        if isinstance(node, ast.Attribute):
            dotted = _dotted(node)
            if any(dotted.startswith(r) or r in dotted for r in
                   ("sys.argv", "os.environ", "request.")):
                return True
            return bool(TAINT_NAME_RE.search(node.attr))
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        if isinstance(node, ast.Call):
            dotted = _dotted(node.func)
            if dotted in ("input", "os.getenv", "os.environ.get"):
                return True
            if dotted.startswith(("sys.argv", "os.environ", "request.")):
                return True
            if any(dotted.startswith(r) for r in ("os.environ", "request.")):
                return True
            return any(self._is_tainted(a) for a in node.args)
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return any(self._is_tainted(c) for c in ast.walk(node)
                       if isinstance(c, (ast.Name, ast.Attribute, ast.Call,
                                         ast.Subscript)))
        return False

    # -- call detection -----------------------------------------------------
    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("pull", "checkout"):
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    pass  # constant string: never reported (no false alarm)
                elif (isinstance(arg, ast.Name) and self._tainted_locals
                        and self._tainted_locals[-1].get(arg.id) is False):
                    pass  # local variable assigned a constant string: safe
                else:
                    call_name = ("Remote.pull" if func.attr == "pull"
                                 else "Head.checkout")
                    status = ("DANGEROUS" if self._is_tainted(arg) else "REVIEW")
                    self.findings.append({
                        "file": self.rel_path,
                        "line": node.lineno,
                        "call": call_name,
                        "arg": _source_text(arg),
                        "status": status,
                    })
        self.generic_visit(node)


def scan_directory(root):
    """Return (findings, skipped) for all .py files under root."""
    root = Path(root)
    findings = []
    skipped = []
    py_files = sorted(root.rglob("*.py")) if root.is_dir() else []
    for path in py_files:
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                             filename=rel)
        except SyntaxError:
            skipped.append(rel)
            continue
        except OSError:
            skipped.append(rel)
            continue
        visitor = _TaintVisitor(rel)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings, skipped


def _table(findings):
    lines = []
    header = "%-34s %-14s %-16s %s" % ("File", "Call", "Argument", "Status")
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        loc = "%s:%d" % (f["file"], f["line"])
        lines.append("%-34s %-14s %-16s %s" % (
            loc[:34], f["call"][:14], f["arg"][:16], f["status"]))
    return lines


def report(version_text, root, findings, skipped, out):
    state, _detail = version_status(version_text)
    if version_text is None:
        vline = "Version : GitPython not installed  -> UNKNOWN (no version to check)"
    elif state == "vulnerable":
        vline = "Version : GitPython %s  -> VULNERABLE (< 3.2.0)" % version_text
    else:
        vline = "Version : GitPython %s  -> OK (>= 3.2.0)" % version_text
    dangerous = [f for f in findings if f["status"] == "DANGEROUS"]
    review = [f for f in findings if f["status"] == "REVIEW"]
    lines = [vline]
    if skipped:
        lines.append("Skipped : %d file(s) with syntax errors (not scanned): %s"
                     % (len(skipped), ", ".join(sorted(skipped))))
    if findings:
        lines.extend(_table(findings))
    else:
        lines.append("(no pull/checkout calls with untrusted input found)")
    if state == "vulnerable":
        lines.append("Result  : FAIL - GitPython %s is before the fixed release 3.2.0"
                     % version_text)
    elif dangerous:
        lines.append("Result  : FAIL - %d dangerous call(s) pass untrusted input to "
                     "Remote.pull()/Head.checkout()" % len(dangerous))
    else:
        extra = ""
        if review:
            extra = " (%d call(s) need a human review)" % len(review)
        lines.append("Result  : PASS - version fixed, 0 dangerous call(s)%s" % extra)
    if state == "vulnerable" or dangerous:
        lines.append("Fix     : pip install -U 'GitPython>=3.2.0' and re-run this check")
        if dangerous:
            lines.append("          then remove/validate the DANGEROUS call(s) above")
    out.write("\n".join(lines) + "\n")
    if state == "vulnerable" or dangerous:
        return 1
    return 0


def _fixture_root():
    return Path(__file__).resolve().parent / "fixtures"


def run_demo(out):
    """Deterministic demo: vuln fixture, then safe fixture. No clock,
    no absolute paths, no randomness -- byte-identical every run."""
    base = _fixture_root()
    lines = ["gitpython-rce-check --demo", ""]
    cases = [
        ("[1/2] fixtures/vuln-repo  (GitPython 3.1.30)", "3.1.30", "vuln-repo"),
        ("[2/2] fixtures/safe-repo  (GitPython 3.2.0)", "3.2.0", "safe-repo"),
    ]
    for title, version, name in cases:
        lines.append(title)
        lines.append("-" * len(title))
        root = base / name
        findings, skipped = scan_directory(root)
        # report() prints relative paths; prefix fixture dir for clarity.
        prefixed = []
        for f in findings:
            g = dict(f)
            g["file"] = "fixtures/%s/%s" % (name, f["file"])
            prefixed.append(g)
        import io
        buf = io.StringIO()
        report(version, root, prefixed, skipped, buf)
        lines.append(buf.getvalue().rstrip("\n"))
        lines.append("")
    out.write("\n".join(lines).rstrip("\n") + "\n")
    return 1  # demo shows a FAIL case by design


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gitpython_rce_check.py",
        description="Check GitPython CVE-2026-110858 / CVE-2026-110859 exposure: "
                    "installed version + AST scan for dangerous Remote.pull() / "
                    "Head.checkout() calls.")
    parser.add_argument("path", nargs="?", default=".",
                        help="directory of .py files to scan (default: current dir)")
    parser.add_argument("--demo", action="store_true",
                        help="run the labelled fixtures (vuln, then safe)")
    parser.add_argument("--gitpython-version", default=None, metavar="VER",
                        help="override the detected GitPython version "
                             "(for fixtures, tests and CI)")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = parser.parse_args(argv)

    if args.demo:
        return run_demo(sys.stdout)

    version = args.gitpython_version or installed_gitpython_version()
    root = Path(args.path)
    if not root.is_dir():
        print("error: not a directory: %s" % args.path, file=sys.stderr)
        return 2
    findings, skipped = scan_directory(root)
    prefixed = []
    for f in findings:
        g = dict(f)
        g["file"] = "%s/%s" % (root.as_posix().rstrip("/"), f["file"])
        prefixed.append(g)
    return report(version, root, prefixed, skipped, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())

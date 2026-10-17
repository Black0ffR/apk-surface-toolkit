"""SH-01 regression tests. Generation only; never executes output."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import unittest

from triagekit import tests_gen


EVIL_PKG = "com.example; touch /tmp/SH_INJECTION"
EVIL_COMP = 'X"$(touch /tmp/SH_INJECTION)"'
EVIL_ACTION = "a; echo injected"
EVIL_AUTH = 'x"; touch /tmp/SH_INJECTION; echo "'
EVIL_URL = 'myscheme://h/p?x=1"; touch /tmp/SH_INJECTION; echo "'


def _evil_report():
    return {
        "package": EVIL_PKG,
        "components": [
            {
                "type": "activity",
                "name": EVIL_COMP,
                "exported": True,
                "intent_filters": [{"actions": [EVIL_ACTION]}],
            },
            {
                "type": "receiver",
                "name": EVIL_COMP,
                "exported": True,
                "intent_filters": [{"actions": [EVIL_ACTION]}],
            },
            {
                "type": "service",
                "name": EVIL_COMP,
                "exported": True,
                "intent_filters": [],
            },
            {
                "type": "provider",
                "name": EVIL_COMP,
                "exported": True,
                "authorities": EVIL_AUTH,
                "intent_filters": [],
            },
        ],
        "custom_schemes": [{"scheme": "myscheme;touch", "host": "h", "component": EVIL_COMP}],
        "app_links": [],
        "findings": [],
    }


class TestShellQuoting(unittest.TestCase):
    def _generate(self, report):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "tests.sh")
            before = set(os.listdir(td))
            tests_gen.generate(report, out)
            # generation must only write the script, not execute anything
            self.assertEqual(set(os.listdir(td)), before | {"tests.sh"})
            with open(out, encoding="utf-8") as f:
                text = f.read()
            return text

    def test_adversarial_values_are_quoted(self):
        text = self._generate(_evil_report())
        # raw unquoted interpolations must be gone
        self.assertNotIn(f"am start -W -n {EVIL_PKG}/{EVIL_COMP}", text)
        self.assertNotIn(f'am broadcast -a {EVIL_ACTION}', text)
        self.assertNotIn(f'content query --uri "content://{EVIL_AUTH}"', text)
        # quoted forms must be present as single shell tokens
        self.assertIn(shlex.quote(EVIL_PKG + "/" + EVIL_COMP), text)
        self.assertIn(shlex.quote(EVIL_ACTION), text)
        self.assertIn(shlex.quote("content://" + EVIL_AUTH), text)
        # package assignment must not be a double-quoted injection
        self.assertNotIn(f'PKG="{EVIL_PKG}"', text)
        self.assertIn(f"PKG={shlex.quote(EVIL_PKG)}", text)

    def test_deeplink_and_comments_are_safe(self):
        text = self._generate(_evil_report())
        # no raw evil URL inside double quotes
        self.assertNotIn(f'-d "{EVIL_URL}"', text)
        # comment lines must not allow newline breakout: a newline inside a
        # component name must not create a new executable line.
        report = _evil_report()
        report["components"][0]["name"] = "evil\ntouch /tmp/SH_INJECTION\nname"
        text2 = self._generate(report)
        for line in text2.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # executable lines must not contain an unsanitized injected newline
            # payload as a bare command
            self.assertFalse(
                stripped.startswith("touch /tmp/SH_INJECTION"),
                f"newline breakout: {line!r}",
            )
        # the sanitized comment must keep the payload on one line
        self.assertNotIn("evil\ntouch", text2)

    def test_generation_does_not_execute(self):
        marker = os.path.join(tempfile.gettempdir(), "SH_INJECTION")
        try:
            if os.path.exists(marker):
                os.remove(marker)
        except OSError:
            pass
        self._generate(_evil_report())
        self.assertFalse(os.path.exists(marker), "generation executed a payload")

    def test_emit_only_by_default(self):
        # generate() has no execute path; cli gate requires explicit --execute + 'run'
        import inspect

        sig = inspect.signature(tests_gen.generate)
        self.assertEqual(list(sig.parameters), ["r", "path"])
        from triagekit import cli as CLI

        src = inspect.getsource(CLI.cmd_analyze)
        with open("triagekit/cli.py", encoding="utf-8") as fh:
            cli_src = fh.read()
        self.assertIn("--execute", cli_src)
        self.assertIn("type 'run' to execute", src)

    def test_bash_syntax_if_available(self):
        text = self._generate(_evil_report())
        try:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".sh", delete=False, encoding="utf-8"
            ) as tf:
                tf.write(text)
                name = tf.name
            try:
                p = subprocess.run(
                    ["bash", "-n", name], capture_output=True, text=True, timeout=30
                )
            except FileNotFoundError:
                self.skipTest("bash unavailable")
            self.assertEqual(p.returncode, 0, f"bash -n failed: {p.stderr[:500]}")
        finally:
            try:
                os.remove(name)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()

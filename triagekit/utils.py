"""Small shared helpers: subprocess safety, paths, hashing, workspace layout."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone

# ---------------------------------------------------------------- subprocess
# Security rule: argv lists, never shell strings. A job file or a manifest value
# must never be able to become a shell token.
def run(cmd: list[str], timeout: int = 120, cwd: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, (p.stdout or p.stderr).strip()
    except FileNotFoundError:
        return 127, "not installed"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def which(name: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def have(*names: str) -> bool:
    return all(which(n) for n in names)


# ---------------------------------------------------------------- paths
def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def confine(path: str, root: str) -> str:
    """Resolve *path* and assert it stays inside *root*.

    Every path that originates from an external file (a job file, a rules file,
    a manifest value) must pass through this before it is used to write.
    """
    rp = os.path.realpath(os.path.abspath(path))
    rr = os.path.realpath(os.path.abspath(root))
    if rp != rr and not rp.startswith(rr + os.sep):
        raise ValueError(f"path escapes workspace: {path!r} not under {root!r}")
    return rp


def workspace(root: str, digest: str) -> str:
    d = os.path.join(root, digest[:12])
    os.makedirs(d, exist_ok=True)
    return d


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- text
_SLUG_BAD = re.compile(r"[^a-z0-9]+")


def slug(s: str) -> str:
    return _SLUG_BAD.sub("-", s.lower()).strip("-") or "x"


def fq(name: str, pkg: str) -> str:
    """Expand a manifest component name to its fully-qualified form."""
    if not name:
        return ""
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return f"{pkg}.{name}"
    return name


def write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def append_jsonl(path: str, obj) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

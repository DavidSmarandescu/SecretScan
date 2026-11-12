"""De dónde salen los archivos a escanear: disco, área de staging o historial."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterator

from . import rules
from .scanner import Finding, scan_line

MAX_FILE_SIZE = 1_000_000
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
              ".mypy_cache", ".pytest_cache", "dist", "build"}
_HUNK = re.compile(r"^@@ -\S+ \+(\d+)")


class GitError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(["git", "-C", str(root), *args],
                                capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise GitError("git no está instalado") from exc
    if result.returncode != 0:
        raise GitError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def git_root(start: Path) -> Path | None:
    try:
        return Path(_git(start, "rev-parse", "--show-toplevel").decode().strip())
    except GitError:
        return None


def _split_z(data: bytes) -> list[str]:
    return [p.decode(errors="surrogateescape") for p in data.split(b"\0") if p]


def staged_files(root: Path) -> Iterator[tuple[str, bytes]]:
    """Contenido tal como quedará en el commit, no el del disco."""
    names = _split_z(_git(root, "diff", "--cached", "--name-only", "-z",
                          "--diff-filter=ACMR"))
    for name in names:
        data = _git(root, "show", f":{name}")
        if len(data) <= MAX_FILE_SIZE:
            yield name, data


def repo_files(root: Path) -> Iterator[tuple[str, bytes]]:
    """Archivos versionados y los nuevos que git no ignora."""
    names = _split_z(_git(root, "ls-files", "-z", "--cached", "--others",
                          "--exclude-standard"))
    for name in sorted(set(names)):
        yield from _read(root / name, name)


def path_files(paths: list[str]) -> Iterator[tuple[str, bytes]]:
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
                for filename in sorted(filenames):
                    full = Path(dirpath) / filename
                    yield from _read(full, full.as_posix())
        else:
            yield from _read(path, path.as_posix())


def _read(full: Path, shown: str) -> Iterator[tuple[str, bytes]]:
    try:
        if full.is_file() and full.stat().st_size <= MAX_FILE_SIZE:
            yield shown, full.read_bytes()
    except OSError:
        return


def find_env_files(root: Path) -> list[Path]:
    """Archivos .env reales en la raíz, de donde se toman los valores a buscar."""
    return sorted(p for p in root.glob(".env*")
                  if p.is_file() and rules.is_env_file(p.name))


def scan_history(root: Path, env_values: dict[str, str] | None = None) -> list[Finding]:
    """Recorre todas las líneas añadidas en cualquier commit.

    Un secreto borrado en un commit posterior sigue siendo recuperable, así que
    se informa del commit más antiguo en el que aparece.
    """
    log = _git(root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0",
               "--format=%x00%H").decode("utf-8", errors="replace")
    found: dict[tuple, Finding] = {}
    commit, path, lineno = "", None, 0
    for line in log.splitlines():
        if line.startswith("\0"):
            commit, path = line[1:8], None
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            if path and (reason := rules.dangerous_file(path)):
                found[(path, "dangerous-file", "")] = Finding(
                    path, 0, "dangerous-file", reason, commit=commit)
                path = None  # no listar además cada línea del archivo
        elif m := _HUNK.match(line):
            lineno = int(m.group(1))
        elif path and line.startswith("+"):
            for f in scan_line(path, lineno, line[1:], env_values):
                f.commit = commit
                # git log va de nuevo a viejo: el último que queda es el origen.
                found[(f.path, f.rule, f.value)] = f
            lineno += 1
    return sorted(found.values(), key=lambda f: (f.path, f.line))

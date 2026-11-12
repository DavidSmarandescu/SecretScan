from __future__ import annotations

import argparse
import json
import stat
import sys
from fnmatch import fnmatch
from pathlib import Path

from . import sources
from .scanner import Finding, parse_env_values, scan_file

IGNORE_FILE = ".secretscanignore"  # un patrón glob por línea

HOOK = """#!/bin/sh
# Instalado por secretscan: bloquea commits que contengan secretos.
PYTHONPATH="{pythonpath}" exec "{python}" -m secretscan --staged
"""


def _install_hook(force: bool) -> int:
    root = sources.git_root(Path.cwd())
    if root is None:
        print("error: no estás dentro de un repositorio git", file=sys.stderr)
        return 2
    hooks = Path(sources._git(root, "rev-parse", "--git-path", "hooks").decode().strip())
    hook = (root / hooks) / "pre-commit"
    if hook.exists() and not force:
        print(f"error: ya existe {hook}; usa --force para sustituirlo", file=sys.stderr)
        return 2
    hook.parent.mkdir(parents=True, exist_ok=True)
    package_parent = Path(__file__).resolve().parent.parent
    hook.write_text(HOOK.format(pythonpath=package_parent, python=sys.executable))
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Hook instalado en {hook}")
    return 0


def _render(findings: list[Finding], reveal: bool) -> str:
    if not findings:
        return "secretscan: sin secretos detectados."
    out = [f"secretscan: {len(findings)} posibles secretos encontrados", ""]
    for f in findings:
        where = f.path if f.line == 0 else f"{f.path}:{f.line}"
        if f.commit:
            where = f"{f.commit} {where}"
        if not f.value:
            shown = ""
        elif reveal:
            shown = f"  → {f.value}"
        else:
            shown = f"  ({len(f.value)} caracteres, valor oculto)"
        out.append(f"  {where}  [{f.rule}] {f.description}{shown}")
    out += ["",
            "Qué hacer: saca el secreto del código (variable de entorno o gestor de",
            "secretos). Si ya se subió a un remoto, rótalo: borrarlo no basta.",
            "Falso positivo: añade el comentario 'secretscan:allow' en esa línea."]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "install-hook":
        return _install_hook(force="--force" in argv[1:])

    ap = argparse.ArgumentParser(
        prog="secretscan",
        description="Busca secretos en el código. Funciona sin red y nunca "
                    "muestra los valores encontrados salvo con --reveal en una "
                    "terminal interactiva. Subcomando extra: install-hook.")
    ap.add_argument("paths", nargs="*",
                    help="archivos o carpetas; por defecto, el repositorio actual")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true",
                      help="solo lo preparado para el próximo commit")
    mode.add_argument("--history", action="store_true",
                      help="todas las líneas añadidas en el historial de git")
    ap.add_argument("--env-file", action="append", default=[], metavar="ARCHIVO",
                    help="archivo .env cuyos valores se buscarán en el código "
                         "(por defecto, los .env de la raíz del repositorio)")
    ap.add_argument("--no-env", action="store_true",
                    help="no leer ningún archivo .env local")
    ap.add_argument("--exclude", action="append", default=[], metavar="PATRÓN",
                    help="patrón glob de rutas a ignorar (repetible)")
    ap.add_argument("--json", action="store_true",
                    help="salida en JSON (nunca incluye los valores)")
    ap.add_argument("--reveal", action="store_true",
                    help="muestra los valores; solo en una terminal interactiva")
    args = ap.parse_args(argv)

    if args.reveal and (args.json or not sys.stdout.isatty()):
        print("error: --reveal solo funciona escribiendo directamente en una "
              "terminal, para que los valores no acaben en archivos, tuberías "
              "ni herramientas automáticas.", file=sys.stderr)
        return 2

    root = sources.git_root(Path.cwd())
    if root is None and (args.staged or args.history or not args.paths):
        print("error: no estás dentro de un repositorio git; indica rutas a "
              "escanear", file=sys.stderr)
        return 2

    env_values: dict[str, str] = {}
    if not args.no_env:
        env_files = [Path(p) for p in args.env_file]
        if not env_files and root is not None:
            env_files = sources.find_env_files(root)
        for env_file in env_files:
            try:
                text = env_file.read_text(errors="replace")
            except OSError as exc:
                print(f"error: no se puede leer {env_file}: {exc.strerror}",
                      file=sys.stderr)
                return 2
            env_values.update(parse_env_values(text, env_file.name))

    try:
        if args.history:
            findings = sources.scan_history(root, env_values)
        else:
            if args.staged:
                files = sources.staged_files(root)
            elif args.paths:
                files = sources.path_files(args.paths)
            else:
                files = sources.repo_files(root)
            findings = [f for path, data in files
                        for f in scan_file(path, data, env_values)]
    except sources.GitError as exc:
        print(f"error de git: {exc}", file=sys.stderr)
        return 2

    excludes = list(args.exclude)
    if root is not None and (ignore := root / IGNORE_FILE).is_file():
        excludes += [line.strip() for line in ignore.read_text().splitlines()
                     if line.strip() and not line.startswith("#")]
    findings = [f for f in findings
                if not any(fnmatch(f.path, glob) for glob in excludes)]

    if args.json:
        print(json.dumps({"findings": [f.to_dict() for f in findings]},
                         indent=2, ensure_ascii=False))
    else:
        print(_render(findings, args.reveal))
    return 1 if findings else 0

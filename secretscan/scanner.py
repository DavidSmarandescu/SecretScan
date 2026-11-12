"""Aplica las reglas a líneas de texto y produce hallazgos."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import rules

ALLOW_PRAGMA = "secretscan:allow"
MAX_LINE = 10_000  # por encima solo se aplican las reglas de formato conocido
MIN_ENV_VALUE = 8


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    description: str
    # El valor solo vive en memoria: no aparece en repr() ni en to_dict().
    value: str = field(repr=False, default="")
    commit: str | None = None

    def to_dict(self) -> dict:
        data = {"path": self.path, "line": self.line, "rule": self.rule,
                "description": self.description, "length": len(self.value)}
        if self.commit:
            data["commit"] = self.commit
        return data


def parse_env_values(text: str, source: str) -> dict[str, str]:
    """Extrae de un .env los valores que merece la pena buscar en el código.

    Devuelve {valor: "archivo:NOMBRE"}. Se descartan valores cortos, numéricos,
    de relleno o URLs sin credenciales, porque aparecerían por todas partes.
    """
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        if (len(value) < MIN_ENV_VALUE or rules.is_placeholder(value)
                or value.replace(".", "").isdigit()
                or (value.lower().startswith(("http://", "https://")) and "@" not in value)):
            continue
        values.setdefault(value, f"{source}:{key.strip()}")
    return values


def scan_line(path: str, lineno: int, line: str,
              env_values: dict[str, str] | None = None) -> list[Finding]:
    if ALLOW_PRAGMA in line:
        return []
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []  # tramos ya atribuidos a una regla más precisa

    def add(span: tuple[int, int], rule: str, description: str, value: str) -> None:
        if any(span[0] < end and start < span[1] for start, end in taken):
            return
        taken.append(span)
        findings.append(Finding(path, lineno, rule, description, value))

    for rule in rules.SPECIFIC_RULES:
        for m in rule.pattern.finditer(line):
            value = m.group(rule.group)
            if rule.group and rules.is_placeholder(value):
                continue
            add(m.span(rule.group), rule.id, rule.description, value)

    for value, origin in (env_values or {}).items():
        start = line.find(value)
        if start != -1:
            add((start, start + len(value)), "env-value",
                f"Valor copiado de {origin}", value)

    if len(line) > MAX_LINE:
        return findings

    patterns = [rules.NAME_QUOTED]
    if rules.is_config_file(path):
        patterns.append(rules.NAME_UNQUOTED)
    for pattern in patterns:
        for m in pattern.finditer(line):
            if rules.name_rule_applies(m.group(1), m.group(2)):
                add(m.span(2), "secret-assignment",
                    f"Valor asignado a '{m.group(1)}'", m.group(2))

    if not rules.skip_entropy(path):
        for m in rules.ENTROPY_CANDIDATE.finditer(line):
            group = 1 if m.group(1) is not None else 2
            if rules.looks_random(m.group(group)):
                add(m.span(group), "high-entropy",
                    "Cadena con aspecto aleatorio", m.group(group))
    return findings


def scan_text(path: str, text: str,
              env_values: dict[str, str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(path, lineno, line, env_values))
    return findings


def scan_file(path: str, data: bytes,
              env_values: dict[str, str] | None = None) -> list[Finding]:
    """Punto de entrada por archivo: nombre peligroso primero, luego contenido."""
    if reason := rules.dangerous_file(path):
        # Un único hallazgo por archivo; listar cada línea no aporta nada.
        return [Finding(path, 0, "dangerous-file", reason)]
    if b"\0" in data[:8192]:
        return []  # binario
    return scan_text(path, data.decode("utf-8", errors="replace"), env_values)

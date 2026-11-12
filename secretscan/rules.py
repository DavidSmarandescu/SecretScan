"""Reglas de detección: formatos conocidos, nombres de variable, entropía
y nombres de archivo peligrosos."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    group: int = 0  # grupo de la regex que contiene el secreto


def _rule(id: str, description: str, regex: str, group: int = 0) -> Rule:
    return Rule(id, description, re.compile(regex), group)


# Capa 1: formatos con prefijo o estructura reconocible. Muy pocos falsos positivos.
SPECIFIC_RULES = (
    _rule("private-key", "Clave privada",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    _rule("aws-access-key", "Clave de acceso de AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _rule("github-token", "Token de GitHub",
          r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    _rule("stripe-key", "Clave de Stripe", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"),
    _rule("slack-token", "Token de Slack", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    _rule("google-api-key", "Clave de API de Google", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _rule("anthropic-key", "Clave de API de Anthropic", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    _rule("openai-key", "Clave de API de OpenAI", r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"),
    _rule("sendgrid-key", "Clave de SendGrid",
          r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    _rule("npm-token", "Token de npm", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("jwt", "Token JWT",
          r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    _rule("url-credentials", "Contraseña dentro de una URL",
          r"\b[a-z][a-z0-9+.\-]*://[^/\s:@\"']+:([^@\s/\"']{3,})@", group=1),
)

# Capa 2: el nombre de la variable delata el contenido.
_KEYWORD = (r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|private[_-]?key|credential)s?")
_NAME = r"([\w.\-]*" + _KEYWORD + r"[\w\-]*)"

# nombre = "valor"  |  "nombre": "valor"  |  nombre => 'valor'
NAME_QUOTED = re.compile(
    r"(?i)(?<![\w.\-])" + _NAME + r"[\"']?\s*(?:=>|:=|:|=)\s*[\"']([^\"'\n]{6,})[\"']")
# NOMBRE=valor sin comillas; solo se aplica a archivos de configuración.
NAME_UNQUOTED = re.compile(
    r"(?i)^\s*(?:export\s+)?" + _NAME + r"\s*[:=]\s*([^\s\"'#]{6,})\s*(?:#.*)?$")

# Variables cuyo nombre contiene una palabra clave pero no guardan un secreto.
_BENIGN_NAME = re.compile(
    r"(?i)(?:url|uri|path|file|dir|name|field|header|type|label|prompt|regex|"
    r"pattern|length|len|expir\w*|ttl|endpoint|policy|rule|hint|min|max)s?$")

CONFIG_SUFFIXES = {".env", ".ini", ".cfg", ".conf", ".properties", ".yml",
                   ".yaml", ".toml"}

# Capa 3: cadenas largas con aspecto aleatorio.
ENTROPY_CANDIDATE = re.compile(
    r"[\"']([A-Za-z0-9+/=_\-]{24,})[\"']|=\s*([A-Za-z0-9+/=_\-]{24,})\s*$")
ENTROPY_THRESHOLD = 4.0
_HEX = re.compile(r"^[0-9a-fA-F]+$")

_PLACEHOLDER_PARTS = (
    "example", "ejemplo", "changeme", "change_me", "change-me", "placeholder",
    "your", "xxxx", "dummy", "redacted", "insert", "replace", "<", ">", "${",
    "{{", "%(", "$(", "****", "....", "environ", "process.env", "getenv",
)
_PLACEHOLDER_WORDS = {
    "password", "passwd", "secret", "token", "string", "bearer", "basic",
    "null", "none", "true", "false", "undefined", "required", "optional",
    "hidden", "text", "apikey", "api_key", "default", "contraseña",
}

# Capa 4: archivos que no deberían estar en un repositorio, contengan lo que contengan.
_DANGEROUS_GLOBS = (
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pypirc", ".netrc",
    ".htpasswd", "credentials.json", "terraform.tfstate", "terraform.tfstate.*",
    "kubeconfig", "*.kdbx",
)
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

# Archivos generados cuyo contenido aleatorio no son secretos.
_SKIP_ENTROPY_GLOBS = ("*.lock", "package-lock.json", "go.sum", "*.min.js",
                       "*.map", "*.svg", "*.ipynb")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def is_placeholder(value: str) -> bool:
    v = value.lower()
    return (v in _PLACEHOLDER_WORDS
            or v.startswith("$")
            or len(set(v)) <= 2
            or any(part in v for part in _PLACEHOLDER_PARTS))


def is_env_file(path: str) -> bool:
    """True para .env y variantes reales (.env.local), no para plantillas."""
    name = PurePosixPath(path).name.lower()
    if name != ".env" and not name.startswith(".env."):
        return False
    return not name.endswith(_ENV_TEMPLATE_SUFFIXES)


def dangerous_file(path: str) -> str | None:
    """Devuelve el motivo si el archivo no debería estar versionado."""
    posix = PurePosixPath(path)
    name = posix.name.lower()
    if is_env_file(path):
        return "Archivo de variables de entorno"
    if any(fnmatch(name, glob) for glob in _DANGEROUS_GLOBS):
        return "Archivo de claves o credenciales"
    if name == "credentials" and posix.parent.name == ".aws":
        return "Credenciales de AWS"
    return None


def is_config_file(path: str) -> bool:
    posix = PurePosixPath(path)
    return posix.suffix.lower() in CONFIG_SUFFIXES or posix.name.lower().startswith(".env")


def skip_entropy(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return any(fnmatch(name, glob) for glob in _SKIP_ENTROPY_GLOBS)


def name_rule_applies(name: str, value: str) -> bool:
    if _BENIGN_NAME.search(name) or is_placeholder(value):
        return False
    if any(ch.isspace() for ch in value):  # frases y mensajes, no secretos
        return False
    if value.startswith(("/", "./", "../", "~/")):  # rutas a archivos
        return False
    if re.match(r"(?i)https?://[^@]*$", value):  # URL sin credenciales
        return False
    return True


def looks_random(value: str) -> bool:
    if is_placeholder(value) or _HEX.match(value):
        return False  # los hashes hexadecimales abundan y casi nunca son secretos
    if value.lower().startswith(("sha1-", "sha256-", "sha384-", "sha512-")):
        return False  # hashes de integridad
    digits = sum(ch.isdigit() for ch in value)
    if digits < 2 or not any(ch.isalpha() for ch in value):
        return False
    return shannon_entropy(value) >= ENTROPY_THRESHOLD

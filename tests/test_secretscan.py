"""Tests del escáner de secretos.

Todas las claves son falsas y se construyen por concatenación, para que este
archivo no contenga ninguna cadena con formato de secreto real.
"""

import ast
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from secretscan import cli, rules, sources
from secretscan.scanner import Finding, parse_env_values, scan_file, scan_line

REPO = Path(__file__).resolve().parent.parent

AWS = "AK" + "IA" + "IOSFODNN7QWERTYU"
GITHUB = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
RANDOM = "q9Zt7Lk2Xw8Vb4Nc6Mj1Hf3Rd5Sg0PaY"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def found(line, path="app.py", env=None):
    return [f.rule for f in scan_line(path, 1, line, env)]


class SpecificRuleTests(unittest.TestCase):
    def test_known_formats(self):
        cases = {
            f'key = "{AWS}"': "aws-access-key",
            f"export GH={GITHUB}": "github-token",
            f"stripe.api_key = '{STRIPE}'": "stripe-key",
            PEM: "private-key",
            "db = 'postgres://admin:" + "s3cr3tPw9" + "@db.internal:5432/app'": "url-credentials",
        }
        for line, rule in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(found(line), [rule])

    def test_url_without_password_is_fine(self):
        self.assertEqual(found("url = 'https://db.internal:5432/app'"), [])
        self.assertEqual(found("url = 'postgres://user:${DB_PASS}@host/db'"), [])


class NameRuleTests(unittest.TestCase):
    def test_assignment_forms(self):
        for line in ('DB_PASSWORD = "hunter2x"',
                     '"api_key": "abc123def"',
                     "config.client_secret = 'm1Secreto'",
                     "auth_token => 'tok12345'"):
            with self.subTest(line=line):
                self.assertEqual(found(line), ["secret-assignment"])

    def test_unquoted_only_in_config_files(self):
        line = "DB_PASSWORD=hunter2x"
        self.assertEqual(found(line, ".env.production"), ["secret-assignment"])
        self.assertEqual(found(line, "config.yml"), ["secret-assignment"])
        self.assertEqual(found(line, "app.py"), [])

    def test_placeholders_and_benign_names_ignored(self):
        for line in ('password = "changeme"',
                     'api_key = "<tu-clave-aqui>"',
                     'token = "${API_TOKEN}"',
                     'password = os.environ["DB_PASSWORD"]',
                     'token_url = "https://auth.internal/oauth"',
                     'password_field = "user_pass"',
                     'private_key_path = "/etc/ssl/server.key"',
                     'password_prompt = "Introduce tu clave: "',
                     'token_type = "bearer"',
                     'secret = "xxxxxxxxxxxx"'):
            with self.subTest(line=line):
                self.assertEqual(found(line), [])


class EntropyTests(unittest.TestCase):
    def test_random_string_detected(self):
        self.assertEqual(found(f'x = "{RANDOM}"'), ["high-entropy"])

    def test_non_secrets_ignored(self):
        for line in ('h = "d41d8cd98f00b204e9800998ecf8427e"',          # hash hex
                     'n = "getUserAccountSettingsByIdentifier"',        # identificador
                     'p = "/usr/local/share/application/data"',         # ruta
                     'm = "Este es un mensaje bastante largo"'):        # texto
            with self.subTest(line=line):
                self.assertEqual(found(line), [])

    def test_lock_files_skipped(self):
        self.assertEqual(found(f'"integrity": "{RANDOM}"', "package-lock.json"), [])

    def test_shannon(self):
        self.assertEqual(rules.shannon_entropy("aaaa"), 0.0)
        self.assertEqual(rules.shannon_entropy("abcd"), 2.0)


class EnvValueTests(unittest.TestCase):
    def test_parse_keeps_only_searchable_values(self):
        values = parse_env_values(
            "# comentario\n"
            "DB_PASS=perro-verde-99\n"
            'QUOTED="valor con espacios 1"\n'
            "PORT=5432\n"
            "DEBUG=true\n"
            "SHORT=abc\n"
            "SITE=https://miweb.internal\n"
            "export API=clave-larga-123 # nota\n", ".env")
        self.assertEqual(values, {"perro-verde-99": ".env:DB_PASS",
                                  "valor con espacios 1": ".env:QUOTED",
                                  "clave-larga-123": ".env:API"})

    def test_value_found_regardless_of_shape(self):
        # Ni el nombre ni el formato delatan nada: solo coincide con el .env.
        env = {"perro-verde-99": ".env:DB_PASS"}
        findings = scan_line("app.py", 3, 'conectar("perro-verde-99")', env)
        self.assertEqual([(f.rule, f.description) for f in findings],
                         [("env-value", "Valor copiado de .env:DB_PASS")])


class FileTests(unittest.TestCase):
    def test_dangerous_files(self):
        for path in (".env", "api/.env.local", "certs/server.pem", "id_rsa",
                     ".aws/credentials", "infra/terraform.tfstate"):
            with self.subTest(path=path):
                findings = scan_file(path, b"X=1\n")
                self.assertEqual([f.rule for f in findings], ["dangerous-file"])

    def test_templates_and_normal_files_allowed(self):
        for path in (".env.example", ".env.sample", "environment.py", "keys.md"):
            with self.subTest(path=path):
                self.assertEqual(scan_file(path, b"X=1\n"), [])

    def test_binary_skipped(self):
        self.assertEqual(scan_file("a.bin", b"\0\0" + AWS.encode()), [])

    def test_allow_pragma(self):
        self.assertEqual(found(f'key = "{AWS}"  # secretscan:allow'), [])

    def test_one_finding_per_secret(self):
        # Coincide con formato conocido, nombre y entropía: se informa una vez.
        self.assertEqual(found(f'api_token = "{GITHUB}"'), ["github-token"])


class PrivacyTests(unittest.TestCase):
    def test_value_never_in_repr_or_dict(self):
        f = Finding("a.py", 1, "aws-access-key", "x", AWS)
        self.assertNotIn(AWS, repr(f))
        self.assertNotIn(AWS, json.dumps(f.to_dict()))
        self.assertEqual(f.to_dict()["length"], len(AWS))

    def test_no_network_modules_imported(self):
        banned = {"socket", "urllib", "http", "requests", "ssl", "ftplib",
                  "smtplib", "asyncio", "xmlrpc"}
        for source in (REPO / "secretscan").glob("*.py"):
            for node in ast.walk(ast.parse(source.read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    self.assertNotIn(name.split(".")[0], banned, source.name)


class GitTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git("init", "-q")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.root)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t",
                        "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
                       check=True, capture_output=True)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_clean_repo(self):
        (self.root / "app.py").write_text("print('hola')\n")
        self.assertEqual(self.run_cli()[0], 0)

    def test_output_hides_value(self):
        (self.root / "app.py").write_text(f'KEY = "{AWS}"\n')
        code, out, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("app.py:1", out)
        self.assertNotIn(AWS, out)
        code, out, _ = self.run_cli("--json")
        self.assertNotIn(AWS, out)
        self.assertEqual(json.loads(out)["findings"][0]["rule"], "aws-access-key")

    def test_reveal_refused_outside_terminal(self):
        (self.root / "app.py").write_text(f'KEY = "{AWS}"\n')
        code, out, err = self.run_cli("--reveal")
        self.assertEqual(code, 2)
        self.assertNotIn(AWS, out + err)

    def test_staged_scans_index_not_disk(self):
        target = self.root / "app.py"
        target.write_text(f'KEY = "{AWS}"\n')
        self.git("add", "app.py")
        target.write_text("KEY = None\n")  # limpio en disco, sucio en staging
        self.assertEqual(self.run_cli("--staged")[0], 1)
        self.git("add", "app.py")
        self.assertEqual(self.run_cli("--staged")[0], 0)

    def test_gitignored_env_supplies_values(self):
        (self.root / ".gitignore").write_text(".env\n")
        (self.root / ".env").write_text("DB_PASS=perro-verde-99\n")
        (self.root / "app.py").write_text('conectar("perro-verde-99")\n')
        code, out, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("Valor copiado de .env:DB_PASS", out)
        self.assertNotIn("perro-verde-99", out)
        self.assertNotIn("dangerous-file", out)  # ignorado por git: no se sube
        self.assertEqual(self.run_cli("--no-env")[0], 0)

    def test_untracked_env_is_flagged(self):
        (self.root / ".env").write_text("DB_PASS=perro-verde-99\n")
        code, out, _ = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("dangerous-file", out)

    def test_history_finds_deleted_secret(self):
        target = self.root / "app.py"
        target.write_text(f'a = 1\nKEY = "{AWS}"\n')
        self.git("add", "."); self.git("commit", "-qm", "uno")
        target.write_text("a = 1\n")
        self.git("add", "."); self.git("commit", "-qm", "dos")
        self.assertEqual(self.run_cli()[0], 0)
        findings = sources.scan_history(self.root)
        self.assertEqual([(f.path, f.line, f.rule) for f in findings],
                         [("app.py", 2, "aws-access-key")])
        self.assertTrue(findings[0].commit)

    def test_install_hook_blocks_commit(self):
        self.assertEqual(self.run_cli("install-hook")[0], 0)
        self.assertEqual(self.run_cli("install-hook")[0], 2)  # no sobrescribe
        (self.root / "app.py").write_text(f'KEY = "{AWS}"\n')
        self.git("add", "app.py")
        with self.assertRaises(subprocess.CalledProcessError):
            self.git("commit", "-qm", "con secreto")
        (self.root / "app.py").write_text("KEY = None\n")
        self.git("add", "app.py")
        self.git("commit", "-qm", "limpio")

    def test_exclude(self):
        (self.root / "fixtures").mkdir()
        (self.root / "fixtures" / "a.py").write_text(f'KEY = "{AWS}"\n')
        self.assertEqual(self.run_cli()[0], 1)
        self.assertEqual(self.run_cli("--exclude", "fixtures/*")[0], 0)


class SelfScanTests(unittest.TestCase):
    def test_this_repository_is_clean(self):
        # Las claves falsas de este archivo se excluyen en .secretscanignore.
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(REPO)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["--no-env"])
        self.assertEqual(code, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()

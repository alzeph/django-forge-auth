"""
Tests de la commande de gestion `forge_auth_setup`
(src/forge_auth/management/commands/forge_auth_setup.py).

Écrit systématiquement dans un fichier temporaire (`--settings-file`),
jamais dans `tests/settings.py` : la commande ajoute un bloc à la fin d'un
vrai fichier, on ne veut surtout pas que ces tests polluent le dépôt.
"""
import importlib.util
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


def _load_forge_auth_dict(path: Path) -> dict:
    spec = importlib.util.spec_from_file_location("generated_settings", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.FORGE_AUTH


class ForgeAuthSetupCommandTestCase(TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        self.settings_path = Path(path)
        self.settings_path.write_text("SECRET_KEY = 'test'\n", encoding="utf-8")
        self.addCleanup(self.settings_path.unlink, missing_ok=True)

    def _run(self, inputs, passwords=None):
        out = StringIO()
        with patch("builtins.input", side_effect=inputs), \
             patch("getpass.getpass", side_effect=(passwords or [])):
            call_command(
                "forge_auth_setup",
                "--settings-file", str(self.settings_path),
                stdout=out,
            )
        return out.getvalue()

    def test_declines_final_confirmation_writes_nothing(self):
        original = self.settings_path.read_text(encoding="utf-8")
        inputs = ["", "", "", "", "", "", "", "", "", "", "", "", "n"]
        output = self._run(inputs)
        self.assertIn("annulée", output)
        self.assertEqual(self.settings_path.read_text(encoding="utf-8"), original)

    def test_all_defaults_produces_valid_forge_auth_dict(self):
        inputs = ["", "", "", "", "", "", "", "", "", "", "", "", "o"]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["USERNAME_FIELD"], "phone_number")
        self.assertEqual(config["OPTIONAL_FIELDS"], [])
        self.assertTrue(config["OTP"]["USE_OTP"])
        self.assertTrue(config["JWT"]["VIA_JSON"])
        self.assertFalse(config["JWT"]["VIA_HTTP_ONLY"])

    def test_toggling_optional_field_off_is_reflected(self):
        inputs = [
            "",       # USERNAME_FIELD default
            "",       # ALTERNATIVE_USERNAME_FIELDS: non
            "2",      # bascule otp_secret
            "",       # valide la sélection de champs
            "",       # valide la sélection de fonctionnalités (otp, jwt)
            "", "", "", "", "",   # sous-questions OTP (5)
            "", "", "",           # sous-questions JWT (3)
            "o",      # confirmation finale
        ]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["OPTIONAL_FIELDS"], ["otp_secret"])

    def test_multi_select_toggle_is_reversible(self):
        """Basculer deux fois le même numéro doit annuler le changement."""
        inputs = [
            "",             # USERNAME_FIELD
            "",             # ALTERNATIVE_USERNAME_FIELDS
            "2,2",          # bascule otp_secret off puis on, dans la même saisie
            "",             # valide
            "",             # valide fonctionnalités
            "", "", "", "", "",
            "", "", "",
            "o",
        ]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["OPTIONAL_FIELDS"], [])

    def test_lockout_feature_adds_account_lockout_key(self):
        inputs = [
            "", "",             # username field, alt field
            "",                 # champs optionnels : valide sans changement
            "3",                # bascule verrouillage de compte (en plus de otp+jwt par défaut)
            "",                 # valide fonctionnalités
            "", "", "", "", "",     # OTP (5 questions)
            "", "", "",             # JWT (3 questions)
            "", "10", "600",        # lockout : activer (défaut oui), max_attempts, duration
            "o",
        ]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["ACCOUNT_LOCKOUT"], {"MAX_ATTEMPTS": 10, "LOCKOUT_DURATION": 600})

    def test_only_jwt_feature_selected_omits_otp_key(self):
        inputs = [
            "", "",
            "",
            "1",            # décoche OTP (retire de la sélection par défaut {otp, jwt})
            "",             # valide fonctionnalités -> reste {jwt}
            "", "", "",     # JWT (3 questions)
            "o",
        ]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertNotIn("OTP", config)
        self.assertIn("JWT", config)

    def test_social_auth_providers_are_collected(self):
        inputs = [
            "", "",
            "",
            "1,2,6",        # décoche otp+jwt (défaut), coche connexion sociale
            "",             # valide fonctionnalités -> {social}
            "o",            # ajouter un fournisseur ? oui
            "google",       # nom
            "https://accounts.google.com",  # issuer
            "my-client-id", # client_id
            "n",            # ajouter un autre fournisseur ? non
            "o",            # confirmation finale
        ]
        self._run(inputs)
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(
            config["SOCIAL_AUTH"],
            {"google": {"ISSUER": "https://accounts.google.com", "CLIENT_ID": "my-client-id"}},
        )

    def test_superuser_password_prompted_via_getpass_and_masked(self):
        inputs = [
            "", "",
            "",
            "1,2,7",        # décoche otp+jwt, coche groupes/superutilisateur
            "",
            "clients,staff",  # GROUPS
            "",               # GROUP_DEFAULT vide
            "",               # username superuser -> défaut "admin"
            "o",              # confirmation finale
        ]
        output = self._run(inputs, passwords=["s3cret!"])
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["GROUPS"], ["clients", "staff"])
        self.assertIsNone(config["GROUP_DEFAULT"])
        self.assertEqual(
            config["CREDENTIALS_SUPERUSER"], {"username": "admin", "password": "s3cret!"}
        )
        # `getpass` masque la saisie au clavier (pas d'écho dans le terminal ni
        # dans l'historique du shell), mais le mot de passe apparaît forcément
        # dans l'aperçu final : il va être écrit en clair dans settings.py de
        # toute façon (même mécanisme que CREDENTIALS_SUPERUSER existant).
        self.assertIn("s3cret!", output)

    def test_warns_and_defaults_admin_password_when_getpass_empty(self):
        inputs = [
            "", "",
            "",
            "1,2,7",
            "",
            "",
            "",
            "",
            "o",
        ]
        output = self._run(inputs, passwords=[""])
        config = _load_forge_auth_dict(self.settings_path)
        self.assertEqual(config["CREDENTIALS_SUPERUSER"]["password"], "admin")
        self.assertIn("mise en production", output)

    def test_aborts_when_forge_auth_already_present_and_user_declines(self):
        self.settings_path.write_text("SECRET_KEY = 'test'\nFORGE_AUTH = {}\n", encoding="utf-8")
        with self.assertRaises(CommandError):
            self._run(["n"])
        self.assertEqual(
            self.settings_path.read_text(encoding="utf-8"), "SECRET_KEY = 'test'\nFORGE_AUTH = {}\n"
        )

    def test_continues_when_forge_auth_already_present_and_user_confirms(self):
        self.settings_path.write_text("SECRET_KEY = 'test'\nFORGE_AUTH = {}\n", encoding="utf-8")
        inputs = ["o", "", "", "", "", "", "", "", "", "", "", "", "", "o"]
        self._run(inputs)
        text = self.settings_path.read_text(encoding="utf-8")
        self.assertEqual(text.count("FORGE_AUTH"), 2)

    def test_missing_settings_file_raises(self):
        with self.assertRaises(CommandError):
            call_command("forge_auth_setup", "--settings-file", "/no/such/file.py")

    def test_keyboard_interrupt_during_wizard_is_handled_gracefully(self):
        out = StringIO()
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            call_command("forge_auth_setup", "--settings-file", str(self.settings_path), stdout=out)
        self.assertIn("annulée", out.getvalue())
        self.assertEqual(self.settings_path.read_text(encoding="utf-8"), "SECRET_KEY = 'test'\n")

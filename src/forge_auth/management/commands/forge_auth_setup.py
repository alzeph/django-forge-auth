"""
Commande de gestion Django : assistant interactif de configuration de
forge_auth.

Usage côté projet hôte (une fois `forge_auth` dans INSTALLED_APPS) :

    uv run manage.py forge_auth_setup

Pose une série de questions (valeurs par défaut proposées entre crochets,
Entrée pour les accepter), affiche un aperçu du dict `FORGE_AUTH` obtenu,
et ne l'ajoute à la fin du fichier de settings qu'après confirmation
explicite. N'écrit jamais si l'utilisateur refuse l'aperçu final.
"""
import getpass
import importlib
import os
import pprint
import re
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

OPTIONAL_FIELD_ITEMS = [
    ("status", "Statut de vérification de compte (status)"),
    ("otp_secret", "Secret OTP applicatif (otp_secret)"),
    ("profile_photo", "Photo de profil (profile_photo)"),
]

FEATURE_ITEMS = [
    ("otp", "Connexion par code OTP (sinon : mot de passe)"),
    ("jwt", "Distribution des tokens JWT (header/cookie, rotation)"),
    ("lockout", "Verrouillage de compte après échecs répétés"),
    ("mfa", "Second facteur TOTP applicatif"),
    ("magic_link", "Connexion sans mot de passe (magic link)"),
    ("social", "Connexion sociale (OIDC)"),
    ("groups", "Groupes et superutilisateur par défaut"),
]


class Command(BaseCommand):
    help = (
        "Assistant interactif de configuration de forge_auth : pose des questions, "
        "propose des valeurs par défaut, et ajoute le dict FORGE_AUTH résultant à la "
        "fin du fichier de settings du projet (après confirmation)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--settings-file",
            dest="settings_file",
            default=None,
            help="Chemin du fichier settings à modifier (déduit de DJANGO_SETTINGS_MODULE si omis).",
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("Assistant de configuration forge_auth"))
        self.stdout.write(
            "Répondez aux questions ci-dessous. Une valeur par défaut entre crochets "
            "est proposée : validez avec Entrée pour l'accepter.\n"
        )

        settings_path = self._resolve_settings_path(options.get("settings_file"))
        self._warn_if_forge_auth_already_present(settings_path)

        try:
            config = self._run_wizard()
        except (EOFError, KeyboardInterrupt):
            self.stdout.write(self.style.WARNING("\n\nConfiguration annulée."))
            return

        block = self._render_block(config)
        self.stdout.write("\n" + self.style.MIGRATE_HEADING("Aperçu du bloc à ajouter") + "\n")
        self.stdout.write(block)

        if not self._ask_yes_no(f"Ajouter ce bloc à la fin de {settings_path} ?", default=False):
            self.stdout.write(self.style.WARNING("Configuration annulée : rien n'a été écrit."))
            return

        with open(settings_path, "a", encoding="utf-8") as f:
            f.write(block)

        self.stdout.write(self.style.SUCCESS(f"\nFORGE_AUTH ajouté à {settings_path}."))
        self._print_next_steps(config)

    # ------------------------------------------------------------------
    # Résolution du fichier settings
    # ------------------------------------------------------------------

    def _resolve_settings_path(self, override: str | None) -> Path:
        if override:
            path = Path(override).resolve()
            if not path.exists():
                raise CommandError(f"Fichier introuvable : {path}")
            return path

        module_name = os.environ.get("DJANGO_SETTINGS_MODULE")
        if not module_name:
            raise CommandError(
                "Impossible de déterminer le fichier de settings "
                "(DJANGO_SETTINGS_MODULE n'est pas défini). Utilisez --settings-file "
                "pour le préciser explicitement."
            )
        module = importlib.import_module(module_name)
        module_file = getattr(module, "__file__", None)
        if not module_file:
            raise CommandError(f"Impossible de localiser le fichier source de {module_name}.")
        return Path(module_file).resolve()

    def _warn_if_forge_auth_already_present(self, settings_path: Path) -> None:
        text = settings_path.read_text(encoding="utf-8")
        if re.search(r"^\s*FORGE_AUTH\s*=", text, re.MULTILINE):
            self.stdout.write(
                self.style.WARNING(
                    "\nATTENTION : 'FORGE_AUTH' est déjà défini dans ce fichier. Python "
                    "exécute le fichier de haut en bas : ajouter un nouveau bloc à la "
                    "fin ÉCRASERA SILENCIEUSEMENT la définition existante à l'exécution."
                )
            )
            if not self._ask_yes_no("Continuer malgré tout ?", default=False):
                raise CommandError("Configuration annulée : 'FORGE_AUTH' existe déjà dans ce fichier.")

    # ------------------------------------------------------------------
    # Rendu du bloc de settings
    # ------------------------------------------------------------------

    def _render_block(self, config: dict) -> str:
        formatted = pprint.pformat(config, indent=4, width=88, sort_dicts=False)
        header = (
            "\n\n# --- Généré par `forge_auth_setup` ---\n"
            "# Modifiable à la main ensuite ; relancer la commande ajoute un nouveau\n"
            "# bloc à la fin (elle ne modifie jamais un bloc déjà présent).\n"
        )
        return f"{header}FORGE_AUTH = {formatted}\n"

    def _print_next_steps(self, config: dict) -> None:
        self.stdout.write(self.style.MIGRATE_HEADING("\nProchaines étapes"))
        tips = [
            "Vérifiez que 'forge_auth' est dans INSTALLED_APPS et que "
            'AUTH_USER_MODEL = "forge_auth.User" est défini.',
            "Ajoutez 'forge_auth.authentification.JWTAuthenticationFlexible' à "
            'REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] si ce n\'est pas déjà fait.',
            "Lancez `python manage.py migrate`.",
        ]
        if "profile_photo" not in config.get("OPTIONAL_FIELDS", []):
            tips.append("Photo de profil activée : configurez MEDIA_ROOT/MEDIA_URL (voir README).")
        if config.get("JWT", {}).get("ROTATE_REFRESH_TOKENS"):
            tips.append(
                "Rotation des refresh tokens activée : ajoutez "
                "'rest_framework_simplejwt.token_blacklist' à INSTALLED_APPS."
            )
        if config.get("SOCIAL_AUTH"):
            tips.append(
                "Connexion sociale configurée : vérifiez que CLIENT_ID/ISSUER correspondent "
                "bien à votre application avant de déployer (voir README, Notes de sécurité)."
            )
        for tip in tips:
            self.stdout.write(f"  • {tip}")

    # ------------------------------------------------------------------
    # Assistant interactif
    # ------------------------------------------------------------------

    def _run_wizard(self) -> dict:
        config: dict = {}

        self.stdout.write(self.style.MIGRATE_HEADING("1. Identifiant de connexion"))
        username_field = self._ask_choice(
            "Quel champ utiliser comme identifiant principal de connexion ?",
            ["phone_number", "email"],
            default=0,
        )
        config["USERNAME_FIELD"] = username_field
        other_field = "email" if username_field == "phone_number" else "phone_number"
        if self._ask_yes_no(f"Accepter aussi '{other_field}' comme identifiant alternatif ?", default=False):
            config["ALTERNATIVE_USERNAME_FIELDS"] = [other_field]
        else:
            config["ALTERNATIVE_USERNAME_FIELDS"] = []

        self.stdout.write(self.style.MIGRATE_HEADING("\n2. Champs du modèle User"))
        enabled = self._ask_multi_select(
            "Cochez les champs à ACTIVER (numéros séparés par des virgules pour basculer, "
            "Entrée pour valider) :",
            OPTIONAL_FIELD_ITEMS,
            default_selected={"status", "otp_secret", "profile_photo"},
        )
        config["OPTIONAL_FIELDS"] = sorted(key for key, _label in OPTIONAL_FIELD_ITEMS if key not in enabled)

        self.stdout.write(self.style.MIGRATE_HEADING("\n3. Fonctionnalités à configurer maintenant"))
        self.stdout.write("(les fonctionnalités non cochées gardent leur valeur par défaut)")
        to_configure = self._ask_multi_select(
            "Cochez les fonctionnalités à configurer :",
            FEATURE_ITEMS,
            default_selected={"otp", "jwt"},
        )

        if "otp" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- OTP --"))
            use_otp = self._ask_yes_no("Activer la connexion par code OTP (sinon mot de passe) ?", default=True)
            otp_conf = {"USE_OTP": use_otp}
            if use_otp:
                otp_conf["OTP_DIGITS"] = self._ask_int("Nombre de chiffres du code", 4)
                otp_conf["OTP_LIFETIME"] = self._ask_int("Durée de vie indicative du code (secondes)", 300)
                otp_conf["OTP_CANAL"] = self._ask_choice(
                    "Canal de distribution du code (métadonnée, l'envoi effectif reste à votre charge)",
                    ["WHATSAPP", "SMS", "MAIL", "APP"],
                    default=0,
                )
            config["OTP"] = otp_conf
            config["REGISTER_INCLUDE_IN_OTP"] = self._ask_yes_no(
                "Créer automatiquement le compte à la première demande d'OTP (auto-inscription) ?",
                default=False,
            )

        if "jwt" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- JWT --"))
            via_json = self._ask_yes_no("Renvoyer access/refresh dans le corps JSON de la réponse ?", default=True)
            via_cookie = self._ask_yes_no("Poser access/refresh en cookies httponly ?", default=False)
            if not via_json and not via_cookie:
                self.stdout.write(self.style.WARNING("Aucun mode choisi : réactivation de VIA_JSON par défaut."))
                via_json = True
            rotate = self._ask_yes_no(
                "Faire tourner (blacklister) le refresh token à chaque /refresh ? "
                "(nécessite rest_framework_simplejwt.token_blacklist)",
                default=False,
            )
            config["JWT"] = {"VIA_JSON": via_json, "VIA_HTTP_ONLY": via_cookie, "ROTATE_REFRESH_TOKENS": rotate}

        if "lockout" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- Verrouillage de compte --"))
            if self._ask_yes_no("Activer le verrouillage de compte après plusieurs échecs ?", default=True):
                config["ACCOUNT_LOCKOUT"] = {
                    "MAX_ATTEMPTS": self._ask_int("Nombre d'échecs avant verrouillage", 5),
                    "LOCKOUT_DURATION": self._ask_int("Durée du verrouillage (secondes)", 900),
                }
            else:
                config["ACCOUNT_LOCKOUT"] = {"MAX_ATTEMPTS": None, "LOCKOUT_DURATION": 900}

        if "mfa" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- MFA TOTP --"))
            config["MFA_TOTP"] = {
                "ISSUER_NAME": self._ask_text("Nom affiché dans l'application d'authentification", "ForgeAuth"),
                "BACKUP_CODES_COUNT": self._ask_int("Nombre de codes de secours générés à l'activation", 10),
            }

        if "magic_link" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- Magic link --"))
            enabled_ml = self._ask_yes_no("Activer la connexion sans mot de passe (magic link) ?", default=True)
            config["MAGIC_LINK"] = {
                "ENABLED": enabled_ml,
                "LIFETIME": self._ask_int("Durée de validité du lien (secondes)", 900) if enabled_ml else 900,
            }

        if "social" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- Connexion sociale (OIDC) --"))
            social: dict = {}
            while self._ask_yes_no(
                "Ajouter un autre fournisseur OIDC (Google, Microsoft...) ?" if social
                else "Ajouter un fournisseur OIDC (Google, Microsoft...) ?",
                default=not social,
            ):
                name = self._ask_text("Nom du fournisseur (clé interne, ex: google)", "").strip().lower()
                if not name:
                    self.stdout.write("Nom vide, ignoré.")
                    continue
                issuer = self._ask_text("URL de l'émetteur (ISSUER)", "https://accounts.google.com")
                client_id = self._ask_text("CLIENT_ID de l'application", "")
                social[name] = {"ISSUER": issuer, "CLIENT_ID": client_id}
            config["SOCIAL_AUTH"] = social

        if "groups" in to_configure:
            self.stdout.write(self.style.MIGRATE_HEADING("\n-- Groupes et superutilisateur --"))
            groups_raw = self._ask_text("Groupes à créer automatiquement (séparés par des virgules)", "")
            config["GROUPS"] = [g.strip() for g in groups_raw.split(",") if g.strip()]
            group_default = self._ask_text(
                "Groupe assigné par défaut aux nouveaux utilisateurs (vide = aucun)", ""
            )
            config["GROUP_DEFAULT"] = group_default or None
            su_username = self._ask_text(
                f"Identifiant ({username_field}) du superutilisateur créé par défaut", "admin"
            )
            su_password = self._ask_password("Mot de passe du superutilisateur par défaut", "admin")
            config["CREDENTIALS_SUPERUSER"] = {"username": su_username, "password": su_password}
            if su_password == "admin":
                self.stdout.write(
                    self.style.WARNING(
                        "Mot de passe par défaut 'admin' conservé : à changer avant la mise en production."
                    )
                )

        return config

    # ------------------------------------------------------------------
    # Primitives d'interaction (mockables via `builtins.input`/`getpass.getpass`)
    # ------------------------------------------------------------------

    def _ask_yes_no(self, prompt: str, default: bool = True) -> bool:
        suffix = "O/n" if default else "o/N"
        while True:
            raw = input(f"{prompt} [{suffix}] : ").strip().lower()
            if not raw:
                return default
            if raw in ("o", "oui", "y", "yes"):
                return True
            if raw in ("n", "non", "no"):
                return False
            self.stdout.write("Réponse non reconnue, tapez o/n.")

    def _ask_choice(self, prompt: str, choices: list, default: int = 0) -> str:
        self.stdout.write(prompt)
        for i, choice in enumerate(choices, start=1):
            marker = " (défaut)" if i - 1 == default else ""
            self.stdout.write(f"  {i}. {choice}{marker}")
        while True:
            raw = input(f"Votre choix [1-{len(choices)}] (Entrée = défaut) : ").strip()
            if not raw:
                return choices[default]
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                return choices[int(raw) - 1]
            self.stdout.write("Choix invalide.")

    def _ask_text(self, prompt: str, default: str = "") -> str:
        raw = input(f"{prompt} [{default}] : ").strip()
        return raw or default

    def _ask_int(self, prompt: str, default: int) -> int:
        while True:
            raw = input(f"{prompt} [{default}] : ").strip()
            if not raw:
                return default
            if raw.lstrip("-").isdigit():
                return int(raw)
            self.stdout.write("Merci d'entrer un nombre entier.")

    def _ask_password(self, prompt: str, default: str) -> str:
        raw = getpass.getpass(f"{prompt} (saisie masquée, Entrée = '{default}') : ")
        return raw or default

    def _ask_multi_select(self, prompt: str, items: list, default_selected: set) -> set:
        """
        Checklist textuelle : réaffiche la liste avec des cases [x]/[ ] à chaque
        tour, l'utilisateur tape les numéros à basculer (ex: "1,3"), Entrée pour
        valider la sélection affichée — le plus proche d'un "défiler et valider"
        atteignable sans dépendance TUI tierce.
        """
        selected = set(default_selected)
        self.stdout.write(prompt)
        while True:
            for i, (key, label) in enumerate(items, start=1):
                mark = "x" if key in selected else " "
                self.stdout.write(f"  [{mark}] {i}. {label}")
            raw = input("Numéros à basculer, ou Entrée pour valider : ").strip()
            if not raw:
                return selected
            picks = []
            valid = True
            for part in raw.split(","):
                part = part.strip()
                if not part.isdigit() or not (1 <= int(part) <= len(items)):
                    valid = False
                    break
                picks.append(int(part))
            if not valid:
                self.stdout.write(self.style.WARNING("Entrée invalide, réessayez."))
                continue
            for p in picks:
                key = items[p - 1][0]
                if key in selected:
                    selected.discard(key)
                else:
                    selected.add(key)

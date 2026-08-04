import logging
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from typing import Literal, List, TypedDict, Any

logger = logging.getLogger(__name__)


class CredentialSuperuserConf:
    username: str = "admin"
    password: str = "admin"

    def __init__(self, **kwargs):
        self.username = kwargs.get("username", "admin")
        self.password = kwargs.get("password", "admin")


class OTPConf:
    USE_OTP: bool = True
    OTP_LIFETIME: int = 300
    OTP_DIGITS: int = 4
    # otp canal peut prendre comme valeur : SMS, APP, MAIL, WHATSAPP
    OTP_CANAL: str = "WHATSAPP"

    def __init__(self, **kwargs):
        self.USE_OTP = bool(kwargs.get("USE_OTP", True))
        self.OTP_LIFETIME = kwargs.get("OTP_LIFETIME", 300)
        self.OTP_DIGITS = kwargs.get("OTP_DIGITS", 4)
        self.OTP_CANAL = kwargs.get("OTP_CANAL", self.OTP_CANAL)


class JWTConf:
    USE_JWT: bool = True
    VIA_JSON: bool = True
    VIA_HTTP_ONLY: bool = False
    ROTATE_REFRESH_TOKENS: bool = False

    def __init__(self, **kwargs):
        self.USE_JWT = bool(kwargs.get("USE_JWT", True))
        self.VIA_JSON = bool(kwargs.get("VIA_JSON", True))
        self.VIA_HTTP_ONLY = bool(kwargs.get("VIA_HTTP_ONLY", False))
        # Nécessite rest_framework_simplejwt.token_blacklist : sans lui,
        # l'ancien refresh token n'est jamais blackliste et reste valide.
        self.ROTATE_REFRESH_TOKENS = bool(kwargs.get("ROTATE_REFRESH_TOKENS", False))


class AccountLockoutConf:
    MAX_ATTEMPTS: int | None = 5
    LOCKOUT_DURATION: int = 900  # secondes

    def __init__(self, **kwargs):
        self.MAX_ATTEMPTS = kwargs.get("MAX_ATTEMPTS", 5)
        self.LOCKOUT_DURATION = kwargs.get("LOCKOUT_DURATION", 900)


class MfaTotpConf:
    ISSUER_NAME: str = "ForgeAuth"
    BACKUP_CODES_COUNT: int = 10

    def __init__(self, **kwargs):
        self.ISSUER_NAME = kwargs.get("ISSUER_NAME", "ForgeAuth")
        self.BACKUP_CODES_COUNT = kwargs.get("BACKUP_CODES_COUNT", 10)


class MagicLinkConf:
    ENABLED: bool = False
    LIFETIME: int = 900  # secondes

    def __init__(self, **kwargs):
        self.ENABLED = bool(kwargs.get("ENABLED", False))
        self.LIFETIME = kwargs.get("LIFETIME", 900)


OPTIONAL_FIELD_TYPE = Literal["status", "otp_secret", "profile_photo"]
USERNAME_FIELD_TYPE = Literal["phone_number", "email"]

class ForgeAuthConfigType(TypedDict, total=False):
    OPTIONAL_FIELDS: List[OPTIONAL_FIELD_TYPE]
    F2FA: bool
    CREDENTIALS_SUPERUSER: CredentialSuperuserConf
    USERNAME_FIELD: USERNAME_FIELD_TYPE
    ALTERNATIVE_USERNAME_FIELDS: List[str]
    OTP: OTPConf
    JWT: JWTConf
    REGISTER_INCLUDE_IN_OTP: bool
    GROUP_DEFAULT: str
    GROUPS: List[str]
    ACCOUNT_LOCKOUT: AccountLockoutConf
    MFA_TOTP: MfaTotpConf
    MAGIC_LINK: MagicLinkConf
    SOCIAL_AUTH: dict

ForgeAuthConfigKeys = Literal[
    "OPTIONAL_FIELDS",
    "F2FA",
    "CREDENTIALS_SUPERUSER",
    "USERNAME_FIELD",
    "ALTERNATIVE_USERNAME_FIELDS",
    "OTP",
    "JWT",
    "REGISTER_INCLUDE_IN_OTP",
    "GROUP_DEFAULT",
    "GROUPS",
    "ACCOUNT_LOCKOUT",
    "MFA_TOTP",
    "MAGIC_LINK",
    "SOCIAL_AUTH",
]

class ForgeAuthConfig:
    """
    Singleton de configuration de FORGE_AUTH.

    Instancié une seule fois en bas de ce fichier sous le nom ``forge_auth_config``.
    La méthode ``validate()`` est appelée par ``AppConfig.ready()`` au
    démarrage de Django : toute erreur de configuration stoppe le serveur.

    Utilisation dans le code :
        from forge_auth.conf import forge_auth_config
        forge_auth_config.get("FIELD")
    """

    _DEFAULTS: ForgeAuthConfigType = {
        "OPTIONAL_FIELDS": [],
        "F2FA": False,
        "CREDENTIALS_SUPERUSER": CredentialSuperuserConf(),
        "USERNAME_FIELD": "phone_number",
        'ALTERNATIVE_USERNAME_FIELDS': [],
        "OTP": OTPConf(),
        "JWT": JWTConf(),
        "REGISTER_INCLUDE_IN_OTP": False,
        # le group par defaut des nouveau utilise si aucun group n'est present leujr de leur création
        "GROUP_DEFAULT": None,
        "GROUPS": [],  # listes des groups a crée dès l'applicatino des migrations
        "ACCOUNT_LOCKOUT": AccountLockoutConf(),
        "MFA_TOTP": MfaTotpConf(),
        "MAGIC_LINK": MagicLinkConf(),
        "SOCIAL_AUTH": {},  # {"google": {"ISSUER": "...", "CLIENT_ID": "..."}, ...}
    }

    AVAILABLE_OPTIONAL_FIELDS: set = {"otp_secret", "status", "profile_photo"}
    AVAILABLE_USERNAME_FIELDS: set = {"phone_number", "email"}

    # Cache interne : None = pas encore résolu
    _resolved: dict | None = None

    def __init__(self):
        self.optional_fields: list = self.get("OPTIONAL_FIELDS")
        self.credentials_superuser_conf: CredentialSuperuserConf = self.get(
            "CREDENTIALS_SUPERUSER")
        self.username_field: str = self.get("USERNAME_FIELD")
        self.otp_conf: OTPConf = self.get("OTP")
        self.jwt_conf: JWTConf = self.get("JWT")
        self.register_include_in_otp: bool = self.get(
            "REGISTER_INCLUDE_IN_OTP")
        self.group_default: str = self.get("GROUP_DEFAULT")
        self.groups: list = self.get("GROUPS")
        self.account_lockout_conf: AccountLockoutConf = self.get("ACCOUNT_LOCKOUT")
        self.mfa_totp_conf: MfaTotpConf = self.get("MFA_TOTP")
        self.magic_link_conf: MagicLinkConf = self.get("MAGIC_LINK")

    def _raw(self) -> dict:
        """Retourne le dict FORGE_AUTH brut depuis settings """
        return getattr(settings, "FORGE_AUTH", {})

    def _merge_conf(self):
        raw = self._raw()
        credential_superuser = CredentialSuperuserConf(
            **raw.get("CREDENTIALS_SUPERUSER", {}))
        otp = OTPConf(**raw.get("OTP", {}))
        jwt = JWTConf(**raw.get("JWT", {}))
        account_lockout = AccountLockoutConf(**raw.get("ACCOUNT_LOCKOUT", {}))
        mfa_totp = MfaTotpConf(**raw.get("MFA_TOTP", {}))
        magic_link = MagicLinkConf(**raw.get("MAGIC_LINK", {}))
        data = {**self._DEFAULTS, **raw}
        data["CREDENTIALS_SUPERUSER"] = credential_superuser
        data["OTP"] = otp
        data["JWT"] = jwt
        data["ACCOUNT_LOCKOUT"] = account_lockout
        data["MFA_TOTP"] = mfa_totp
        data["MAGIC_LINK"] = magic_link
        return data

    def get(self, key: ForgeAuthConfigKeys) -> Any:
        """
        Retourne la valeur de *key* (depuis FORGE_AUTH ou la valeur par défaut).

        Le cache est rempli lors du premier appel si validate() n'a pas encore
        été appelé (cas des imports effectués avant AppConfig.ready()).
        """
        if self._resolved is None:
            self._resolved = self._merge_conf()
        return self._resolved.get(key, self._DEFAULTS[key])

    def validate(self) -> None:
        raw = self._raw()
        errors: list[str] = []

        unknown_keys = set(raw) - set(self._DEFAULTS)
        if unknown_keys:
            errors.append(
                f"Clés inconnues : {unknown_keys}. "
                f"Clés valides : {set(self._DEFAULTS)}"
            )

        # validation de OPTIONAL_FIELDS
        optional_fields = raw.get(
            "OPTIONAL_FIELDS", self._DEFAULTS["OPTIONAL_FIELDS"])
        if not isinstance(optional_fields, (list, tuple, set)):
            errors.append(
                f"'OPTIONAL_FIELDS' doit peut être une liste,  un tuple ou un set de str, "
                f"reçu : {type(optional_fields).__name__}"
            )
        else:
            bad = set(optional_fields) - self.AVAILABLE_OPTIONAL_FIELDS
            if bad:
                errors.append(
                    f"'OPTIONAL_FIELDS' contient des valeurs invalides : {bad}. "
                    f"Valeurs acceptées : {self.AVAILABLE_OPTIONAL_FIELDS}"
                )

        # verificatino de CREDENTIALS_SUPERUSER
        credentials_superuser = raw.get("CREDENTIALS_SUPERUSER", {})
        if not isinstance(credentials_superuser, dict):
            errors.append(
                f"'CREDENTIALS_SUPERUSER' doit être un dict, "
                f"reçu : {type(credentials_superuser).__name__}"
            )

        # validation de USERNAME_FIELD
        username_field = raw.get(
            "USERNAME_FIELD", self._DEFAULTS["USERNAME_FIELD"])
        if username_field not in self.AVAILABLE_USERNAME_FIELDS:
            errors.append(
                f"'USERNAME_FIELD' = '{username_field}' est invalide. "
                f"Valeurs acceptées : {self.AVAILABLE_USERNAME_FIELDS}"
            )

        # validation de OTP
        otp = raw.get("OTP", {})
        if not isinstance(otp, dict):
            errors.append(
                f"'OTP' doit peut être un dict, "
                f"reçu : {type(otp).__name__}"
            )

        jwt = raw.get("JWT", {})
        if not isinstance(jwt, dict):
            errors.append(
                f"'JWT' doit peut être un dict, "
                f"reçu : {type(jwt).__name__}"
            )

        for key in ("ACCOUNT_LOCKOUT", "MFA_TOTP", "MAGIC_LINK"):
            value = raw.get(key, {})
            if not isinstance(value, dict):
                errors.append(
                    f"'{key}' doit être un dict, reçu : {type(value).__name__}"
                )

        # validation de SOCIAL_AUTH : {provider_name: {ISSUER, CLIENT_ID}}
        social_auth = raw.get("SOCIAL_AUTH", {})
        if not isinstance(social_auth, dict):
            errors.append(
                f"'SOCIAL_AUTH' doit être un dict, reçu : {type(social_auth).__name__}"
            )
        else:
            for provider, provider_conf in social_auth.items():
                if not isinstance(provider_conf, dict):
                    errors.append(
                        f"'SOCIAL_AUTH[\"{provider}\"]' doit être un dict, "
                        f"reçu : {type(provider_conf).__name__}"
                    )
                    continue
                missing = {"ISSUER", "CLIENT_ID"} - set(provider_conf)
                if missing:
                    errors.append(
                        f"'SOCIAL_AUTH[\"{provider}\"]' : clés manquantes {missing}"
                    )

        # Résultat
        if errors:
            bullet_list = "\n".join(f"  • {e}" for e in errors)
            raise ImproperlyConfigured(
                f"Configuration FORGE_AUTH invalide ({len(errors)} erreur(s)) :\n"
                + bullet_list
            )

        # Mise en cache après validation réussie
        self._resolved = {**self._DEFAULTS, **raw}
        logger.debug("forge_auth – configuration FORGE_AUTH validée avec succès.")

    def get_username_field(self) -> USERNAME_FIELD_TYPE:
        return self.get("USERNAME_FIELD")
    
    def get_alternative_username_fields(self) -> List[USERNAME_FIELD_TYPE]:
        return self.get("ALTERNATIVE_USERNAME_FIELDS")
    
    def is_username_field(self, field_name: USERNAME_FIELD_TYPE) -> bool:
        return field_name == self.get_username_field() or field_name in self.get_alternative_username_fields()

    def is_enabled_field(self, field_name: OPTIONAL_FIELD_TYPE) -> bool:
        return field_name not in self.get('OPTIONAL_FIELDS')

    def reset(self) -> None:
        """
        Vide le cache interne.
        Utile dans les tests qui modifient settings via @override_settings.
        """
        self._resolved = None


forge_auth_config = ForgeAuthConfig()

import logging
import secrets
from datetime import timedelta

import pyotp

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    Group,
    Permission,
    PermissionsMixin,
)
from django.core.validators import validate_email
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from forge_auth.conf import forge_auth_config

logger = logging.getLogger(__name__)


class UserManager(BaseUserManager):
    """Manager personnalisé : authentification par numéro de téléphone."""

    def create_user(self, password=None, **extra_fields):
        username_field = forge_auth_config.get_username_field()
        username = extra_fields.get(username_field, None)

        if not username:
            logger.error("create_user: %s manquant, création annulée", username_field)
            raise ValueError(_(f"Le {username_field} est obligatoire."))
        groups = extra_fields.pop("groups", None)
        permissions = extra_fields.pop("user_permissions", None)
        user = self.model(**extra_fields)
        user.set_password(password)
        user.save()

        if groups:
            if isinstance(groups, list):
                # Accepte un mélange d'instances Group et de noms (str).
                names = [g.name if isinstance(g, Group) else g for g in groups]
                groups = Group.objects.filter(name__in=names)
                logger.debug("create_user: ajout de %d groupes à l'utilisateur %s", len(groups), username)
                user.groups.set(groups or [])
        else:
            group_default = forge_auth_config.get("GROUP_DEFAULT")
            if group_default:
                default_group, _created = Group.objects.get_or_create(name=group_default)
                user.groups.add(default_group)
                logger.debug("create_user: groupe par défaut '%s' assigné à %s", group_default, username)
        if permissions:
            if isinstance(permissions, list):
                # Accepte un mélange d'instances Permission et de codenames (str).
                # Avant ce correctif : `codename__in=permissions` comparait
                # `codename` à `str(instance)` (ex. "app | model | Can add
                # model") quand une instance Permission était passée, donc ne
                # matchait jamais rien (contrairement à Group, dont le
                # `__str__` vaut justement `name` par coïncidence).
                codenames = [p.codename if isinstance(p, Permission) else p for p in permissions]
                permissions = Permission.objects.filter(codename__in=codenames)
                logger.debug("create_user: ajout de %d permissions à l'utilisateur %s", len(permissions), username)
                user.user_permissions.set(permissions or [])

        logger.info("create_user: utilisateur créé (%s=%s)", username_field, username)
        return user

    def create_superuser(self, password=None, **extra_fields):
        username_field = forge_auth_config.get_username_field()
        username = extra_fields.get(username_field, None)
        if not username:
            logger.error("create_superuser: %s manquant, création annulée", username_field)
            raise ValueError(_(f"Le {username_field} est obligatoire."))
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        logger.debug("create_superuser: création d'un superutilisateur (%s=%s)", username_field, username)
        return self.create_user(password, **extra_fields)


class OtpSecretMixin(models.Model):
    """
    Ajoute le champ `otp_secret` au modèle User.

    Ce mixin est inclus uniquement si `otp_secret` n'est PAS dans
    `OPTIONAL_FIELDS`. Le secret est généré automatiquement via
    pyotp et n'est pas modifiable depuis l'interface d'administration.
    """

    otp_secret = models.CharField(
        max_length=32,
        default=pyotp.random_base32,
        editable=False,
        null=False,
        verbose_name=_("Secret OTP"),
        help_text=_(
            "Clé secrète TOTP de l'utilisateur (générée automatiquement)."),
    )

    class Meta:
        abstract = True


class StatusMixin(models.Model):
    """
    Ajoute le champ ``status`` et les propriétés associées au modèle User.

    Ce mixin est inclus uniquement si "status" n'est PAS dans
    FORGE_AUTH["OPTIONAL_FIELDS"].
    """

    class StatusVerified(models.TextChoices):
        UNVERIFIED = "unverified",  _("Non vérifié")
        VERIFIED = "verified",    _("Vérifié")
        BLOCKED = "blocked",     _("Bloqué")
        SUSPENDED = "suspended",   _("Suspendu")
        DELETED = "deleted",     _("Supprimé")
        DEACTIVATED = "deactivated", _("Désactivé")

    status = models.CharField(
        max_length=20,
        choices=StatusVerified.choices,
        default=StatusVerified.UNVERIFIED,
        verbose_name=_("Statut de vérification"),
    )

    # --- propriétés pratiques -----------------------------------------------

    @property
    def is_verified(self) -> bool:
        """True si le compte a été vérifié."""
        return self.status == self.StatusVerified.VERIFIED

    @property
    def is_unauthorized(self) -> bool:
        """True si le compte est bloqué, suspendu, supprimé ou désactivé."""
        return self.status in (
            self.StatusVerified.BLOCKED,
            self.StatusVerified.SUSPENDED,
            self.StatusVerified.DELETED,
            self.StatusVerified.DEACTIVATED,
        )
    
    def delete_user(self):
        self.status = self.StatusVerified.DELETED
        self.save(update_fields=["status"])
    
    def deactivate_user(self):
        self.status = self.StatusVerified.DEACTIVATED
        self.save(update_fields=["status"])

    def mark_as_verified(self):
        self.status = self.StatusVerified.VERIFIED
        self.save(update_fields=["status"])
    
    def mark_as_unverified(self):
        self.status = self.StatusVerified.UNVERIFIED
        self.save(update_fields=["status"])

    def mark_as_suspended(self):
        self.status = self.StatusVerified.SUSPENDED
        self.save(update_fields=["status"])

    class Meta:
        abstract = True


class ProfilePhotoMixin(models.Model):
    """
    Ajoute le champ ``profile_photo`` au modèle User.

    Ce mixin est inclus uniquement si `profile_photo` n'est PAS dans
    `OPTIONAL_FIELDS`. Nécessite Pillow (dépendance de `django-forge-auth`)
    et un stockage de fichiers configuré côté projet hôte (MEDIA_ROOT/
    MEDIA_URL, ou un backend `django-storages` pour S3/GCS...).
    """

    profile_photo = models.ImageField(
        upload_to="forge_auth/profile_photos/",
        null=True,
        blank=True,
        verbose_name=_("Photo de profil"),
    )

    class Meta:
        abstract = True


def _build_user_bases() -> tuple:
    """
    Construit la liste des classes parentes de User en fonction des champs
    activés dans FORGE_AUTH["OPTIONAL_FIELDS"].

    Retourne un tuple de classes prêt à être utilisé comme bases de User.
    """
    bases: list = [AbstractBaseUser, PermissionsMixin]

    if "otp_secret" not in forge_auth_config.optional_fields:
        bases.insert(0, OtpSecretMixin)

    if "status" not  in forge_auth_config.optional_fields:
        bases.insert(0, StatusMixin)

    if "profile_photo" not in forge_auth_config.optional_fields:
        bases.insert(0, ProfilePhotoMixin)

    return tuple(bases)


class User(*_build_user_bases()):
    """
    Modèle utilisateur principal de scb_auth.

    L'authentification se fait (USERNAME_FIELD).

    Champs toujours présents
    ------------------------
    first_name, last_name, phone_number, email, password,
    last_login, is_staff, is_active, is_superuser,
    groups, user_permissions, date_joined.

    Champs conditionnels (désactivables via FORGE_AUTH["OPTIONAL_FIELDS"])
    --------------------------------------------------------------------
    otp_secret       – secret TOTP (via OtpSecretMixin)
    status           – statut de vérification (via StatusMixin)
    profile_photo    – photo de profil (via ProfilePhotoMixin)
    """
    username_field = forge_auth_config.get_username_field()
   

    first_name = models.CharField(max_length=30, null=True, blank=True, verbose_name=_("Prénom"))
    last_name  = models.CharField(max_length=30, null=True, blank=True, verbose_name=_("Nom"))
    phone_number = models.CharField(
        max_length=20,
        unique= forge_auth_config.is_username_field("phone_number"),
        null=  not forge_auth_config.is_username_field("phone_number"),
        blank= not forge_auth_config.is_username_field("phone_number"),
        verbose_name=_("Numéro de téléphone"),
    )
    email = models.EmailField(
        unique= forge_auth_config.is_username_field("email"),
        blank=not forge_auth_config.is_username_field("email"),
        null=not forge_auth_config.is_username_field("email"),
        verbose_name=_("Adresse e-mail"),
    )
    password = models.CharField(max_length=128, blank=True, null=True, verbose_name=_("Mot de passe"))
    last_login  = models.DateTimeField(null=True, blank=True)
    is_staff    = models.BooleanField(default=False)
    is_active   = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    groups = models.ManyToManyField(Group, blank=True, verbose_name=_("Groupes"))
    user_permissions = models.ManyToManyField(
        Permission, blank=True, verbose_name=_("Permissions")
    )
    date_joined = models.DateTimeField(auto_now_add=True, verbose_name=_("Date d'inscription"))
    # Verrouillage de compte (FORGE_AUTH["ACCOUNT_LOCKOUT"]) : toujours présents
    # (légers), la fonctionnalité elle-même est désactivable via
    # ACCOUNT_LOCKOUT.MAX_ATTEMPTS = None.
    failed_login_attempts = models.PositiveIntegerField(default=0, editable=False, verbose_name=_("Échecs de connexion consécutifs"))
    locked_until = models.DateTimeField(null=True, blank=True, editable=False, verbose_name=_("Verrouillé jusqu'à"))
    objects = UserManager()
    USERNAME_FIELD  = forge_auth_config.get_username_field()
    REQUIRED_FIELDS = []

    @property
    def username(self):
        return getattr(self, self.USERNAME_FIELD)

    @property
    def full_name(self) -> str:
        """Retourne le nom complet « Prénom Nom »."""
        return f"{self.first_name} {self.last_name}"

    @property
    def is_valid_email(self) -> bool:
        """True si l'adresse e-mail est syntaxiquement valide."""
        try:
            validate_email(self.email)
            return True
        except Exception:
            return False
    
    @property
    def is_valid_phone_number(self) -> bool:
        """True si le numéro de téléphone est syntaxiquement valide."""
        try:
            return self.phone_number[1:].isdigit()
        except Exception:
            return False

    @property
    def is_locked(self) -> bool:
        """True si le compte est temporairement verrouillé (voir ACCOUNT_LOCKOUT)."""
        return bool(self.locked_until and self.locked_until > timezone.now())

    def register_failed_login(self) -> None:
        """
        Incrémente le compteur d'échecs de connexion et verrouille le compte
        si `ACCOUNT_LOCKOUT.MAX_ATTEMPTS` est atteint. No-op si MAX_ATTEMPTS
        est None/0 (fonctionnalité désactivée).
        """
        conf = forge_auth_config.account_lockout_conf
        if not conf.MAX_ATTEMPTS:
            return
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= conf.MAX_ATTEMPTS:
            self.locked_until = timezone.now() + timedelta(seconds=conf.LOCKOUT_DURATION)
            logger.warning("register_failed_login: compte verrouillé jusqu'à %s pour user=%s", self.locked_until, self)
        self.save(update_fields=["failed_login_attempts", "locked_until"])

    def register_successful_login(self) -> None:
        """Réinitialise le compteur d'échecs après une connexion réussie."""
        if self.failed_login_attempts or self.locked_until:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save(update_fields=["failed_login_attempts", "locked_until"])

    @staticmethod
    def get(username: str) -> "User":
        """
        Récupère l'utilisateur correspondant au username fourni.
        Paramètres
        ----------
        username : str

        Retourne
        --------
        User

        Lève
        ----
        User.DoesNotExist
            Si aucun utilisateur n'est trouvé.
        PermissionError
            Si le compte est supprimé (status == DELETED),
            uniquement quand le champ status est activé.
        """
        username_field = forge_auth_config.get_username_field()
        alt_username_field = forge_auth_config.get_alternative_username_fields()

        login_fields = list(set([username_field] + list(alt_username_field)))

        query = Q()
        for field in login_fields:
            if field:
                query |= Q(**{f"{field}__iexact": username})

        try:
            user = User.objects.get(query)
        except User.DoesNotExist:
            logger.debug("User.get: aucun utilisateur trouvé pour %s", username)
            raise User.DoesNotExist(f"Utilisateur introuvable : {username}")

        if 'status' not in forge_auth_config.optional_fields:
            if user.status == StatusMixin.StatusVerified.DELETED:
                logger.warning("User.get: tentative d'accès à un compte supprimé (%s)", username)
                raise PermissionError("Ce compte a été supprimé.")
        return user

    def __str__(self) -> str:
        username_field = forge_auth_config.get_username_field()
        return getattr(self, username_field)

    class Meta:
        verbose_name          = _("utilisateur")
        verbose_name_plural   = _("utilisateurs")
        ordering              = ("-date_joined",)
        unique_together       = ("phone_number", "email")

# OtpToken n'est créé que si USE_OTP=True ET otp_secret est activé.
_use_otp = forge_auth_config.otp_conf.USE_OTP
_otp_enabled =  "otp_secret" not in forge_auth_config.optional_fields

if _use_otp and _otp_enabled:

    class OtpToken(models.Model):
        """
        Jeton OTP à usage temporaire lié à un utilisateur.

        Ce modèle n'existe que si FORGE_AUTH["OTP"]["USE_OTP"] est True (défaut)
        ET que "otp_secret" n'est pas dans FORGE_AUTH["OPTIONAL_FIELDS"].
        """

        user = models.OneToOneField(
            User,
            on_delete=models.CASCADE,
            related_name="otp_token",
            verbose_name=_("Utilisateur"),
        )
        token      = models.CharField(max_length=255, verbose_name=_("Token haché"))
        otp_code = models.CharField(max_length=255, null=True, blank=True, verbose_name=_("Code OTP"))
        created_at = models.DateTimeField(auto_now_add=True)
        updated_at = models.DateTimeField(auto_now=True)

        def generate_otp(self, digits: int | None = None) -> str:
            """
            Génère un nouveau code OTP pour l'utilisateur associé.

            Le nombre de chiffres est lu depuis FORGE_AUTH["OTP"]["OTP_DIGITS"]
            (défaut : 4) mais peut être surchargé par le paramètre *digits*.

            Paramètres
            ----------
            digits : int, optional
                Nombre de chiffres du code OTP.
            Retourne
            --------
            str
                Le code OTP en clair (à transmettre à l'utilisateur).
            """
            nb_digits = digits or forge_auth_config.otp_conf.OTP_DIGITS
            totp = pyotp.TOTP(self.user.otp_secret, digits=nb_digits)
            code = totp.now()
            self.token = make_password(code)
            self.otp_code = code
            self.save()
            # Le code n'est volontairement pas loggé (donnée sensible).
            logger.info("generate_otp: nouveau code OTP (%s chiffres) généré pour user=%s", nb_digits, self.user)
            return code
        

        def verify_otp(self, code: str) -> bool:
            """
            Vérifie si le code OTP fourni correspond au token stocké.

            En mode DEBUG, la vérification est toujours True.

            Paramètres
            ----------
            code : str
                Code OTP saisi par l'utilisateur.

            Retourne
            --------
            bool
                True si le code est valide (ou si DEBUG=True).
            """
            if getattr(settings, "DEBUG", True):
                logger.debug("verify_otp: DEBUG=True, vérification bypassée pour user=%s", self.user)
                return True
            is_valid = check_password(code, self.token)
            if not is_valid:
                logger.warning("verify_otp: code OTP invalide pour user=%s", self.user)
            return is_valid

        class Meta:
            verbose_name        = _("jeton OTP")
            verbose_name_plural = _("jetons OTP")

else:
    # Classe fantôme pour permettre les imports sans erreur
    # ("from forge_auth.models import OtpToken" ne plantera pas,
    #  mais instancier OtpToken lèvera NotImplementedError)
    class OtpToken:  # type: ignore[no-redef]
        """
        Placeholder : OtpToken est désactivé dans la configuration actuelle.

        Activez-le en mettant FORGE_AUTH["OTP"]["USE_OTP"] = True
        et en retirant "otp_secret" de FORGE_AUTH["OPTIONAL_FIELDS"].
        """

        def __init__(self, *args, **kwargs):
            raise NotImplementedError(
                "OtpToken est désactivé. "
                "Activez-le en mettant  USE_OTP=True"
            )


class SessionMetadata(models.Model):
    """
    Métadonnées d'une session (un refresh token émis), pour la gestion des
    appareils/sessions ("lister mes sessions actives", "déconnecter cet
    appareil précis").

    Volontairement pas de ForeignKey vers
    `rest_framework_simplejwt.token_blacklist.models.OutstandingToken` :
    `jti` est stocké en simple CharField pour ne pas rendre ce modèle (et sa
    migration) dépendants de l'installation de `token_blacklist`. `revoke()`
    blackliste malgré tout le token correspondant si `token_blacklist` est
    disponible (voir `_revoke_outstanding_tokens` dans `views.py`).
    """

    user = models.ForeignKey(
        "forge_auth.User", on_delete=models.CASCADE, related_name="sessions",
        verbose_name=_("Utilisateur"),
    )
    jti = models.CharField(max_length=255, unique=True, verbose_name=_("JTI du refresh token"))
    user_agent = models.CharField(max_length=255, blank=True, default="", verbose_name=_("User-Agent"))
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name=_("Adresse IP"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Créée le"))
    last_seen_at = models.DateTimeField(auto_now=True, verbose_name=_("Dernière activité"))
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Révoquée le"))

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def revoke(self) -> None:
        """Marque la session comme révoquée et blackliste le refresh token associé (si possible)."""
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])
        try:
            from rest_framework_simplejwt.token_blacklist.models import (
                BlacklistedToken, OutstandingToken,
            )
        except ImportError:
            return
        try:
            outstanding = OutstandingToken.objects.get(jti=self.jti)
        except OutstandingToken.DoesNotExist:
            return
        BlacklistedToken.objects.get_or_create(token=outstanding)
        logger.info("SessionMetadata.revoke: session %s révoquée pour user=%s", self.jti, self.user)

    class Meta:
        verbose_name = _("session")
        verbose_name_plural = _("sessions")
        ordering = ("-last_seen_at",)


class LoginAuditLog(models.Model):
    """
    Historique des tentatives de connexion (réussies ou échouées), pour audit
    de sécurité et affichage côté utilisateur ("dernières connexions").

    `user` est nullable : un échec sur un identifiant inconnu doit rester
    tracé (utile pour repérer une campagne de brute force), sans pouvoir
    être rattaché à un utilisateur réel.
    """

    class Result(models.TextChoices):
        SUCCESS = "success", _("Succès")
        FAILURE = "failure", _("Échec")

    user = models.ForeignKey(
        "forge_auth.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="login_audit_logs", verbose_name=_("Utilisateur"),
    )
    username_attempted = models.CharField(max_length=255, blank=True, default="", verbose_name=_("Identifiant saisi"))
    result = models.CharField(max_length=10, choices=Result.choices, verbose_name=_("Résultat"))
    reason = models.CharField(max_length=255, blank=True, default="", verbose_name=_("Motif"))
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name=_("Adresse IP"))
    user_agent = models.CharField(max_length=255, blank=True, default="", verbose_name=_("User-Agent"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Horodatage"))

    class Meta:
        verbose_name = _("historique de connexion")
        verbose_name_plural = _("historiques de connexion")
        ordering = ("-created_at",)


class ApiKey(models.Model):
    """
    Clé d'API pour l'authentification machine-à-machine (voir
    `authentification.py::ApiKeyAuthentication`).

    La clé en clair n'est jamais stockée : seul son hash (`make_password`,
    même mécanisme que les mots de passe) est conservé. `prefix` (préfixe de
    la clé en clair, non secret) permet de retrouver rapidement la ligne
    candidate sans avoir à `check_password` sur toutes les clés existantes.
    """

    user = models.ForeignKey(
        "forge_auth.User", on_delete=models.CASCADE, related_name="api_keys",
        verbose_name=_("Utilisateur"),
    )
    name = models.CharField(max_length=100, verbose_name=_("Nom"))
    prefix = models.CharField(max_length=12, editable=False, db_index=True, verbose_name=_("Préfixe"))
    hashed_key = models.CharField(max_length=128, editable=False, verbose_name=_("Clé (hachée)"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Créée le"))
    last_used_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Dernière utilisation"))
    revoked_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Révoquée le"))

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @staticmethod
    def generate_key() -> tuple[str, str, str]:
        """Retourne (clé en clair, préfixe, hash). La clé en clair n'est jamais stockée."""
        raw_key = secrets.token_urlsafe(32)
        prefix = raw_key[:12]
        return raw_key, prefix, make_password(raw_key)

    def verify_key(self, raw_key: str) -> bool:
        return check_password(raw_key, self.hashed_key)

    def revoke(self) -> None:
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked_at"])

    class Meta:
        verbose_name = _("clé API")
        verbose_name_plural = _("clés API")
        ordering = ("-created_at",)


class TotpDevice(models.Model):
    """
    Second facteur TOTP applicatif (Google Authenticator, Authy...),
    indépendant de l'OTP SMS/WhatsApp de connexion (`OtpToken`) : celui-ci
    sert de méthode de connexion à part entière selon `FORGE_AUTH["OTP"]`,
    alors que `TotpDevice` est un facteur additionnel, activé volontairement
    par l'utilisateur, vérifié en plus du mot de passe.
    """

    user = models.OneToOneField(
        "forge_auth.User", on_delete=models.CASCADE, related_name="totp_device",
        verbose_name=_("Utilisateur"),
    )
    secret = models.CharField(max_length=32, default=pyotp.random_base32, editable=False, verbose_name=_("Secret TOTP"))
    confirmed = models.BooleanField(default=False, verbose_name=_("Confirmé"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Créé le"))

    def provisioning_uri(self) -> str:
        """URI `otpauth://` à encoder en QR code côté client (app d'authentification)."""
        issuer = forge_auth_config.mfa_totp_conf.ISSUER_NAME
        return pyotp.TOTP(self.secret).provisioning_uri(name=self.user.username, issuer_name=issuer)

    def verify(self, code: str) -> bool:
        return pyotp.TOTP(self.secret).verify(code, valid_window=1)

    def generate_backup_codes(self) -> list[str]:
        """
        (Re)génère les codes de secours : supprime les anciens et en crée de
        nouveaux. Retourne les codes en clair (à afficher une seule fois).
        """
        count = forge_auth_config.mfa_totp_conf.BACKUP_CODES_COUNT
        self.backup_codes.all().delete()
        plain_codes = [secrets.token_hex(4) for _i in range(count)]
        TotpBackupCode.objects.bulk_create([
            TotpBackupCode(device=self, code_hash=make_password(code))
            for code in plain_codes
        ])
        logger.info("generate_backup_codes: %d codes de secours régénérés pour user=%s", count, self.user)
        return plain_codes

    def consume_backup_code(self, code: str) -> bool:
        """Vérifie un code de secours et le marque comme utilisé (usage unique)."""
        for backup_code in self.backup_codes.filter(used_at__isnull=True):
            if check_password(code, backup_code.code_hash):
                backup_code.used_at = timezone.now()
                backup_code.save(update_fields=["used_at"])
                return True
        return False

    class Meta:
        verbose_name = _("appareil TOTP")
        verbose_name_plural = _("appareils TOTP")


class TotpBackupCode(models.Model):
    device = models.ForeignKey(TotpDevice, on_delete=models.CASCADE, related_name="backup_codes")
    code_hash = models.CharField(max_length=128, verbose_name=_("Code (haché)"))
    used_at = models.DateTimeField(null=True, blank=True, verbose_name=_("Utilisé le"))

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    class Meta:
        verbose_name = _("code de secours TOTP")
        verbose_name_plural = _("codes de secours TOTP")


class SocialAccount(models.Model):
    """
    Compte social lié (connexion OIDC, voir `FORGE_AUTH["SOCIAL_AUTH"]`).

    `(provider, subject)` identifie de façon stable le compte chez le
    fournisseur (`subject` = claim `sub` de l'id_token) : c'est cette paire,
    pas l'email, qui sert de clé de liaison (une adresse email peut changer
    ou ne pas être vérifiée par le fournisseur).
    """

    user = models.ForeignKey(
        "forge_auth.User", on_delete=models.CASCADE, related_name="social_accounts",
        verbose_name=_("Utilisateur"),
    )
    provider = models.CharField(max_length=50, verbose_name=_("Fournisseur"))
    subject = models.CharField(max_length=255, verbose_name=_("Identifiant chez le fournisseur (sub)"))
    email = models.EmailField(blank=True, default="", verbose_name=_("E-mail communiqué par le fournisseur"))
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Lié le"))

    class Meta:
        verbose_name = _("compte social")
        verbose_name_plural = _("comptes sociaux")
        unique_together = ("provider", "subject")

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, exceptions
from django.db import transaction
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from forge_auth import social
from forge_auth.conf import forge_auth_config
from forge_auth.models import ApiKey, LoginAuditLog, OtpToken, SessionMetadata

logger = logging.getLogger(__name__)

User = get_user_model()


def _run_password_validators(password: str, user=None) -> None:
    """
    Applique les validateurs `AUTH_PASSWORD_VALIDATORS` du projet hôte.
    Convertit les erreurs Django en `serializers.ValidationError` DRF.
    """
    try:
        validate_password(password, user=user)
    except DjangoValidationError as exc:
        raise serializers.ValidationError({"password": list(exc.messages)})


def _client_ip(request) -> str | None:
    return request.META.get("REMOTE_ADDR") if request is not None else None


def _client_user_agent(request) -> str:
    return (request.META.get("HTTP_USER_AGENT", "") if request is not None else "")[:255]


def _log_login_attempt(request, *, result: str, user=None, username: str = "", reason: str = "") -> None:
    """
    Écrit une entrée dans `LoginAuditLog`. Volontairement défensif (n'importe
    quelle erreur d'écriture est avalée) : un problème sur ce journal d'audit
    ne doit jamais faire échouer une connexion par ailleurs valide.
    """
    try:
        LoginAuditLog.objects.create(
            user=user,
            username_attempted=username or "",
            result=result,
            reason=reason,
            ip_address=_client_ip(request),
            user_agent=_client_user_agent(request),
        )
    except Exception:
        logger.exception("_log_login_attempt: échec de l'écriture de l'audit log")


def _check_not_locked(user, request=None, username: str = "") -> None:
    """Lève `AuthenticationFailed` si le compte est temporairement verrouillé (voir ACCOUNT_LOCKOUT)."""
    if user.is_locked:
        logger.warning("_check_not_locked: compte verrouillé pour %s", user)
        _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="locked")
        raise exceptions.AuthenticationFailed(
            _("Compte temporairement verrouillé suite à plusieurs échecs de connexion.")
        )


def _verify_totp_if_enabled(user, attrs: dict, request=None, username: str = "") -> None:
    """
    Si l'utilisateur a activé un second facteur TOTP applicatif
    (`TotpDevice.confirmed=True` — voir "MFA TOTP applicatif" dans le
    README, indépendant de l'OTP SMS/WhatsApp qui sert de méthode de
    connexion principale), exige et vérifie `totp_code` ou `backup_code`
    en plus du mot de passe/OTP déjà validé. No-op si aucun device confirmé.
    """
    device = getattr(user, "totp_device", None)
    if not device or not device.confirmed:
        return

    totp_code = attrs.get('totp_code')
    backup_code = attrs.get('backup_code')

    if totp_code and device.verify(totp_code):
        return
    if backup_code and device.consume_backup_code(backup_code):
        return

    logger.warning("_verify_totp_if_enabled: code TOTP/secours invalide ou manquant pour %s", user)
    user.register_failed_login()
    _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="invalid_totp")
    raise exceptions.AuthenticationFailed(
        _("Code d'authentification à deux facteurs invalide ou manquant")
    )


def _ensure_account_usable(user) -> None:
    """
    Vérifie qu'un compte authentifié par mot de passe ou OTP est utilisable :
    - `is_active=False` (désactivé côté Django/admin) ;
    - `status` (si activé) dans BLOCKED/SUSPENDED/DELETED/DEACTIVATED
      (`user.is_unauthorized`).
    Lève `exceptions.AuthenticationFailed` sinon.

    Nécessaire car le flux JWT de forge_auth n'appelle jamais
    `django.contrib.auth.authenticate()` (qui ferait normalement cette
    vérification via `ModelBackend.user_can_authenticate`) : il vérifie le
    mot de passe/OTP directement sur l'instance `User`.
    """
    if not user.is_active:
        logger.warning("_ensure_account_usable: compte désactivé (is_active=False) pour %s", user)
        raise exceptions.AuthenticationFailed(_("Ce compte est désactivé."))
    if getattr(user, "is_unauthorized", False):
        logger.warning("_ensure_account_usable: compte non autorisé (status=%s) pour %s", getattr(user, "status", None), user)
        raise exceptions.AuthenticationFailed(_("Ce compte n'est pas autorisé à se connecter."))


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['pk', 'name', 'permissions']
        
class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['pk', 'name', 'content_type', 'codename']

global_fields = [
    'pk', 'first_name', 'last_name', 'phone_number', 'email',
    'last_login', 'is_staff', 'is_active', 'is_superuser',
    'groups', 'groups_detail', 'user_permissions', 'date_joined',
    'password',
] 
def _visible_user_fields() -> list:
    fields = list(global_fields)
    if 'status' not in forge_auth_config.optional_fields:
        fields.append('status')
    if 'profile_photo' not in forge_auth_config.optional_fields:
        fields.append('profile_photo')
    return fields


class UserSerializer(serializers.ModelSerializer):
    groups_detail = GroupSerializer(source='groups', many=True, read_only=True)
    user_permissions = PermissionSerializer(many=True, read_only=True)
    groups = serializers.ListField(required=False, child=serializers.CharField(), write_only=True)
    class Meta:
        model = User
        fields = _visible_user_fields()

        extra_kwargs = {
            'pk': {'read_only': True},
            'last_login': {'read_only': True},
            'is_staff': {'read_only': True},
            'is_active': {'read_only': True},
            'is_superuser': {'read_only': True},
            'password': {'write_only': True, 'required': False},
            'user_permissions': {'read_only': True},
            'date_joined': {'read_only': True},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        password = attrs.get('password')
        if password:
            _run_password_validators(password, user=self.instance)
        return attrs

    def create(self, validated_data):
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            logger.info("UserSerializer.create: nouvel utilisateur créé (%s)", user)
            return user

    def update(self, instance, validated_data):
        """
        Surchargé car `ModelSerializer.update()` ferait `setattr(instance,
        "password", value)` puis `instance.save()` : le mot de passe serait
        alors stocké EN CLAIR (pas de hachage). Idem pour `groups`, qui est
        une liste de noms (str) côté API et non des instances/pk `Group`
        attendues par `field.set()`.
        """
        password = validated_data.pop('password', None)
        group_names = validated_data.pop('groups', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()

        if group_names is not None:
            groups = Group.objects.filter(name__in=group_names)
            instance.groups.set(groups)

        logger.info("UserSerializer.update: utilisateur mis à jour (%s)", instance)
        return instance

class UsernameSerializer(serializers.Serializer):
    username = serializers.CharField()

    def validate_username(self, value):
        username_field = forge_auth_config.get_username_field()
        if not value:
            logger.warning("UsernameSerializer: username manquant")
            raise serializers.ValidationError(_("username est obligatoire"))
        if forge_auth_config.register_include_in_otp:
            # `_user` (pas `_`) : `_` est l'alias de gettext_lazy dans ce
            # module, l'assigner ici en ferait une variable locale et
            # casserait `_("...")` plus haut dans cette même fonction
            # (UnboundLocalError, Python capture `_` comme local dès qu'il
            # est assigné n'importe où dans le corps de la fonction).
            _user, created = User.objects.get_or_create(**{username_field: value})
            if created:
                logger.info("UsernameSerializer: utilisateur créé à la volée via obtain_otp (%s=%s)", username_field, value)
            return value
        if User.objects.filter(**{username_field: value}).exists():
            return value
        logger.warning("UsernameSerializer: utilisateur inconnu (%s=%s)", username_field, value)
        raise serializers.ValidationError(_("L'utilisateur n'existe pas"))
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
    totp_code = serializers.CharField(required=False)
    backup_code = serializers.CharField(required=False)

    def validate(self, attrs):

        """
        permet de verifier l'authentification
        """

        attrs = super().validate(attrs)

        username = attrs.get('username')
        code = attrs.get('code')
        password = attrs.get('password')
        request = self.context.get('request')

        logger.debug("LoginSerializer.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializer.validate: utilisateur introuvable ou inaccessible (%s)", username)
            _log_login_attempt(request, username=username, result=LoginAuditLog.Result.FAILURE, reason="unknown_user")
            raise exceptions.AuthenticationFailed(_("Identifiants incorrects"))

        _check_not_locked(user, request, username)

        if 'otp_secret' not in forge_auth_config.optional_fields and forge_auth_config.otp_conf.USE_OTP:
            if not code:
                logger.warning("LoginSerializer.validate: code OTP manquant pour %s", username)
                raise exceptions.AuthenticationFailed(_("Code OTP obligatoire"))
            try:
                otp_token = user.otp_token
            except OtpToken.DoesNotExist:
                logger.warning("LoginSerializer.validate: aucun OTP demandé pour %s", username)
                raise exceptions.AuthenticationFailed(_("Aucun code OTP n'a été demandé"))
            if not otp_token.verify_otp(code):
                logger.warning("LoginSerializer.validate: code OTP incorrect pour %s", username)
                user.register_failed_login()
                _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="invalid_otp")
                raise exceptions.AuthenticationFailed(_("Code incorrect"))

        else:
            if not password:
                logger.warning("LoginSerializer.validate: mot de passe manquant pour %s", username)
                raise exceptions.AuthenticationFailed(_("Mot de passe obligatoire"))
            if not user.check_password(password):
                logger.warning("LoginSerializer.validate: mot de passe incorrect pour %s", username)
                user.register_failed_login()
                _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="invalid_password")
                raise exceptions.AuthenticationFailed(_("Mot de passe incorrect"))

        _verify_totp_if_enabled(user, attrs, request, username)

        try:
            _ensure_account_usable(user)
        except exceptions.AuthenticationFailed:
            _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="account_unusable")
            raise

        user.register_successful_login()
        _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.SUCCESS)
        logger.debug("LoginSerializer.validate: authentification réussie pour %s", username)
        attrs['user'] = user
        return attrs

class LoginSerializerF2FA_STEP1(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(required=True)

    def validate(self, attrs):

        """
        permet de verifier l'authentification
        """

        attrs = super().validate(attrs)
        username = attrs.get('username')
        password = attrs.get('password')
        request = self.context.get('request')

        logger.debug("LoginSerializerF2FA_STEP1.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializerF2FA_STEP1.validate: utilisateur introuvable ou inaccessible (%s)", username)
            _log_login_attempt(request, username=username, result=LoginAuditLog.Result.FAILURE, reason="unknown_user")
            raise exceptions.AuthenticationFailed(_("Identifiants incorrects"))

        _check_not_locked(user, request, username)

        if not password:
                logger.warning("LoginSerializer.validate: mot de passe manquant pour %s", username)
                raise exceptions.AuthenticationFailed(_("Mot de passe obligatoire"))
        if not user.check_password(password):
                logger.warning("LoginSerializer.validate: mot de passe incorrect pour %s", username)
                user.register_failed_login()
                _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="invalid_password")
                raise exceptions.AuthenticationFailed(_("Mot de passe incorrect"))

        try:
            _ensure_account_usable(user)
        except exceptions.AuthenticationFailed:
            _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="account_unusable")
            raise

        # Pas de LoginAuditLog "success" ici : l'étape 1 du F2FA ne délivre
        # aucun JWT (voir LoginSerializerF2FA_STEP2), ce n'est pas une
        # connexion complète — seulement un mot de passe correct, qui
        # réinitialise malgré tout le compteur de verrouillage.
        user.register_successful_login()
        logger.debug("LoginSerializer.validate: authentification réussie pour %s", username)
        attrs['user'] = user
        return attrs

class LoginSerializerF2FA_STEP2(serializers.Serializer):
    username = serializers.CharField()
    code = serializers.CharField(required=True)
    totp_code = serializers.CharField(required=False)
    backup_code = serializers.CharField(required=False)

    def validate(self, attrs):

        """
        permet de verifier l'authentification
        """

        attrs = super().validate(attrs)

        username = attrs.get('username')
        code = attrs.get('code')
        request = self.context.get('request')

        logger.debug("LoginSerializerF2FA_STEP2.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializerF2FA_STEP2.validate: utilisateur introuvable ou inaccessible (%s)", username)
            _log_login_attempt(request, username=username, result=LoginAuditLog.Result.FAILURE, reason="unknown_user")
            raise exceptions.AuthenticationFailed(_("Identifiants incorrects"))

        _check_not_locked(user, request, username)

        if 'otp_secret' in forge_auth_config.optional_fields or not forge_auth_config.otp_conf.USE_OTP:
            logger.warning("LoginSerializerF2FA_STEP2.validate: OTP désactivé pour cette configuration, connexion refusée pour %s", username)
            raise exceptions.AuthenticationFailed(_("OTP désactivé pour cette configuration"))

        if not code:
            logger.warning("LoginSerializerF2FA_STEP2.validate: code OTP manquant pour %s", username)
            raise exceptions.AuthenticationFailed(_("Code OTP obligatoire"))
        try:
            otp_token = user.otp_token
        except OtpToken.DoesNotExist:
            logger.warning("LoginSerializerF2FA_STEP2.validate: aucun OTP demandé pour %s", username)
            raise exceptions.AuthenticationFailed(_("Aucun code OTP n'a été demandé"))
        if not otp_token.verify_otp(code):
            logger.warning("LoginSerializerF2FA_STEP2.validate: code OTP incorrect pour %s", username)
            user.register_failed_login()
            _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="invalid_otp")
            raise exceptions.AuthenticationFailed(_("Code incorrect"))

        _verify_totp_if_enabled(user, attrs, request, username)

        try:
            _ensure_account_usable(user)
        except exceptions.AuthenticationFailed:
            _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.FAILURE, reason="account_unusable")
            raise

        user.register_successful_login()
        _log_login_attempt(request, user=user, username=username, result=LoginAuditLog.Result.SUCCESS)
        attrs['user'] = user
        return attrs


class LoginSuccessSerializer(serializers.Serializer):
    user = UserSerializer()
    access = serializers.CharField()
    refresh = serializers.CharField()
    
class RefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)
    access = serializers.CharField(required=False, read_only=True)
    
    def validate(self, attrs):
        attrs = super().validate(attrs)
        refresh = attrs.get('refresh')
        try:
            token = RefreshToken(refresh)
        except TokenError as e:
            # `TokenError` est une simple `Exception`, pas une
            # `APIException` DRF : la laisser remonter telle quelle
            # provoquait une 500 (non gérée) au lieu d'une 401 propre.
            logger.warning("RefreshSerializer.validate: refresh token invalide : %s", e)
            raise InvalidToken(str(e))
        # Exposés comme attributs (pas dans `attrs`, pour ne pas fuiter dans
        # le corps JSON de la réponse) : utilisés par
        # `views.py::_sync_session_on_refresh` pour faire suivre le jti à
        # SessionMetadata quand la rotation change l'identifiant de session.
        self._old_jti = token["jti"]
        attrs['access'] = str(token.access_token)

        if forge_auth_config.jwt_conf.ROTATE_REFRESH_TOKENS:
            try:
                token.blacklist()
            except Exception as e:
                # AttributeError si token_blacklist n'est pas installé (la
                # méthode n'existe alors même pas sur la classe), ou toute
                # autre erreur DB : on rotate quand même, mais l'ancien
                # refresh token reste valide jusqu'à son expiration naturelle.
                logger.warning(
                    "RefreshSerializer.validate: échec du blacklist de l'ancien refresh token lors de la rotation : %s", e
                )
            token.set_jti()
            token.set_exp()
            token.set_iat()
            self._new_jti = token["jti"]
            attrs['refresh'] = str(token)
            logger.debug("RefreshSerializer.validate: refresh token rotaté")

        logger.debug("RefreshSerializer.validate: access token régénéré")
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """
    Changement de mot de passe par un utilisateur déjà authentifié.
    Nécessite `context={'request': request}` (fourni automatiquement par
    `GenericAPIView.get_serializer`).
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            logger.warning("ChangePasswordSerializer: ancien mot de passe incorrect pour %s", user)
            raise serializers.ValidationError(_("Mot de passe actuel incorrect"))
        return value

    def validate_new_password(self, value):
        user = self.context['request'].user
        _run_password_validators(value, user=user)
        return value

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])
        logger.info("ChangePasswordSerializer: mot de passe changé pour %s", user)
        return user


class RequestPasswordResetSerializer(serializers.Serializer):
    """
    Demande de réinitialisation de mot de passe. Volontairement minimal :
    l'existence de l'utilisateur est vérifiée côté vue (voir
    `UserViewSet.request_password_reset`), qui décide de la réponse à
    renvoyer si l'identifiant est inconnu.
    """
    username = serializers.CharField()


class ConfirmPasswordResetSerializer(serializers.Serializer):
    username = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        username = attrs['username']
        token = attrs['token']
        new_password = attrs['new_password']

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("ConfirmPasswordResetSerializer.validate: utilisateur introuvable ou inaccessible (%s)", username)
            raise exceptions.AuthenticationFailed(_("Lien de réinitialisation invalide ou expiré"))

        if not default_token_generator.check_token(user, token):
            logger.warning("ConfirmPasswordResetSerializer.validate: token invalide ou expiré pour %s", username)
            raise exceptions.AuthenticationFailed(_("Lien de réinitialisation invalide ou expiré"))

        _run_password_validators(new_password, user=user)
        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])
        logger.info("ConfirmPasswordResetSerializer: mot de passe réinitialisé pour %s", user)
        return user


CONTACT_VERIFICATION_SALT = "forge_auth.contact_verification"
_CONTACT_VERIFICATION_MAX_AGE = 60 * 60 * 24  # 24h

CONTACT_VERIFICATION_FIELDS = ["email", "phone_number"]


class RequestContactVerificationSerializer(serializers.Serializer):
    """
    Demande de vérification d'un champ de contact (email ou téléphone) de
    l'utilisateur authentifié. Le token généré encode la valeur actuelle du
    champ : s'il change avant la confirmation, l'ancien token est
    automatiquement invalidé (voir ConfirmContactVerificationSerializer).
    """
    field = serializers.ChoiceField(choices=CONTACT_VERIFICATION_FIELDS)

    def validate_field(self, value):
        user = self.context['request'].user
        if not getattr(user, value, None):
            raise serializers.ValidationError(_("Ce champ n'est pas renseigné sur votre compte."))
        return value

    def make_token(self) -> str:
        user = self.context['request'].user
        field = self.validated_data['field']
        return signing.dumps(
            {"pk": user.pk, "field": field, "value": getattr(user, field)},
            salt=CONTACT_VERIFICATION_SALT,
        )


class ConfirmContactVerificationSerializer(serializers.Serializer):
    field = serializers.ChoiceField(choices=CONTACT_VERIFICATION_FIELDS)
    token = serializers.CharField()

    def validate(self, attrs):
        attrs = super().validate(attrs)
        user = self.context['request'].user
        try:
            payload = signing.loads(attrs['token'], salt=CONTACT_VERIFICATION_SALT, max_age=_CONTACT_VERIFICATION_MAX_AGE)
        except signing.BadSignature:
            raise exceptions.AuthenticationFailed(_("Lien de vérification invalide ou expiré"))
        if payload.get("pk") != user.pk or payload.get("field") != attrs['field']:
            raise exceptions.AuthenticationFailed(_("Lien de vérification invalide ou expiré"))
        if payload.get("value") != getattr(user, attrs['field']):
            raise exceptions.ValidationError(
                _("Ce lien correspond à une ancienne valeur de ce champ, redemandez une vérification.")
            )
        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        if hasattr(user, "mark_as_verified"):
            user.mark_as_verified()
        logger.info("ConfirmContactVerificationSerializer: %s vérifié pour %s", self.validated_data['field'], user)
        return user


class TotpConfirmSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate_code(self, value):
        user = self.context['request'].user
        device = getattr(user, "totp_device", None)
        if not device:
            raise serializers.ValidationError(_("Aucune configuration TOTP en attente : appelez d'abord mfa-totp-setup."))
        if not device.verify(value):
            raise serializers.ValidationError(_("Code invalide."))
        return value


class TotpDisableSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Mot de passe incorrect."))
        return value


class MagicLinkRequestSerializer(serializers.Serializer):
    username = serializers.CharField()


MAGIC_LINK_SALT = "forge_auth.magic_link"


class MagicLinkConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        attrs = super().validate(attrs)
        try:
            payload = signing.loads(
                attrs['token'], salt=MAGIC_LINK_SALT, max_age=forge_auth_config.magic_link_conf.LIFETIME
            )
        except signing.BadSignature:
            raise exceptions.AuthenticationFailed(_("Lien de connexion invalide ou expiré"))
        try:
            user = User.objects.get(pk=payload["pk"])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Lien de connexion invalide ou expiré"))
        _ensure_account_usable(user)
        attrs['user'] = user
        return attrs


class ApiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = ApiKey
        fields = ['pk', 'name', 'prefix', 'created_at', 'last_used_at', 'revoked_at']
        read_only_fields = fields


class CreateApiKeySerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)


class RevokeApiKeySerializer(serializers.Serializer):
    key_id = serializers.IntegerField()


class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = SessionMetadata
        fields = ['pk', 'user_agent', 'ip_address', 'created_at', 'last_seen_at']
        read_only_fields = fields


class RevokeSessionSerializer(serializers.Serializer):
    session_id = serializers.IntegerField()


class LoginAuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginAuditLog
        fields = ['pk', 'result', 'reason', 'ip_address', 'user_agent', 'created_at']
        read_only_fields = fields


class SocialLoginSerializer(serializers.Serializer):
    """
    Connexion via un fournisseur OIDC configuré dans
    FORGE_AUTH["SOCIAL_AUTH"]. Le client obtient l'id_token via le SDK du
    fournisseur (côté web/mobile) et le transmet ici ; `provider` doit
    correspondre à une clé de SOCIAL_AUTH.
    """
    provider = serializers.CharField()
    id_token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        provider = attrs['provider']
        provider_conf = forge_auth_config.get("SOCIAL_AUTH").get(provider)
        if not provider_conf:
            raise serializers.ValidationError({"provider": _("Fournisseur non configuré.")})
        try:
            claims = social.verify_id_token(
                attrs['id_token'], issuer=provider_conf['ISSUER'], audience=provider_conf['CLIENT_ID']
            )
        except Exception as e:
            logger.warning("SocialLoginSerializer.validate: id_token invalide pour provider=%s : %s", provider, e)
            raise exceptions.AuthenticationFailed(_("Jeton d'identité invalide ou expiré."))
        if not claims.get("sub"):
            raise exceptions.AuthenticationFailed(_("Jeton d'identité invalide : claim 'sub' manquant."))
        attrs['claims'] = claims
        return attrs


class ExistsResponseSerializer(serializers.Serializer):
    exists = serializers.BooleanField()

class VerifyFieldSerializer(serializers.Serializer):
    verify = serializers.EmailField()
    exclude = serializers.EmailField(required=False)

class NotFound404ResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()
    
class DetailResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()

class ValidationError400Serializer(serializers.Serializer):
    field_name = serializers.ListField(
        child=serializers.CharField(),
        help_text="Liste des messages d'erreur liés à ce champ."
    )
   
class ResultResponseSerializer(serializers.Serializer):
    result = serializers.BooleanField()

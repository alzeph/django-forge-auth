import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers, exceptions
from django.db import transaction
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from forge_auth.conf import forge_auth_config
from forge_auth.models import OtpToken

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
        raise exceptions.AuthenticationFailed("Ce compte est désactivé.")
    if getattr(user, "is_unauthorized", False):
        logger.warning("_ensure_account_usable: compte non autorisé (status=%s) pour %s", getattr(user, "status", None), user)
        raise exceptions.AuthenticationFailed("Ce compte n'est pas autorisé à se connecter.")


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
class UserSerializer(serializers.ModelSerializer):
    groups_detail = GroupSerializer(source='groups', many=True, read_only=True)
    user_permissions = PermissionSerializer(many=True, read_only=True)
    groups = serializers.ListField(required=False, child=serializers.CharField(), write_only=True)
    class Meta:
        model = User
        fields = global_fields + ['status'] if 'status'  not in forge_auth_config.optional_fields else global_fields
        
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
            raise serializers.ValidationError("username est obligatoire")
        if forge_auth_config.register_include_in_otp:
            _, created = User.objects.get_or_create(**{username_field: value})
            if created:
                logger.info("UsernameSerializer: utilisateur créé à la volée via obtain_otp (%s=%s)", username_field, value)
            return value
        if User.objects.filter(**{username_field: value}).exists():
            return value
        logger.warning("UsernameSerializer: utilisateur inconnu (%s=%s)", username_field, value)
        raise serializers.ValidationError("L'utilisateur n'existe pas")
    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(required=False)
    code = serializers.CharField(required=False)
    
    def validate(self, attrs):
        
        """
        permet de verifier l'authentification
        """
        
        attrs = super().validate(attrs)
        
        username = attrs.get('username')
        code = attrs.get('code')
        password = attrs.get('password')

        logger.debug("LoginSerializer.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializer.validate: utilisateur introuvable ou inaccessible (%s)", username)
            raise exceptions.AuthenticationFailed("Identifiants incorrects")

        if 'otp_secret' not in forge_auth_config.optional_fields and forge_auth_config.otp_conf.USE_OTP:
            if not code:
                logger.warning("LoginSerializer.validate: code OTP manquant pour %s", username)
                raise exceptions.AuthenticationFailed("Code OTP obligatoire")
            try:
                otp_token = user.otp_token
            except OtpToken.DoesNotExist:
                logger.warning("LoginSerializer.validate: aucun OTP demandé pour %s", username)
                raise exceptions.AuthenticationFailed("Aucun code OTP n'a été demandé")
            if not otp_token.verify_otp(code):
                logger.warning("LoginSerializer.validate: code OTP incorrect pour %s", username)
                raise exceptions.AuthenticationFailed("Code incorrect")

        else:
            if not password:
                logger.warning("LoginSerializer.validate: mot de passe manquant pour %s", username)
                raise exceptions.AuthenticationFailed("Mot de passe obligatoire")
            if not user.check_password(password):
                logger.warning("LoginSerializer.validate: mot de passe incorrect pour %s", username)
                raise exceptions.AuthenticationFailed("Mot de passe incorrect")
        _ensure_account_usable(user)
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

        logger.debug("LoginSerializerF2FA_STEP1.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializerF2FA_STEP1.validate: utilisateur introuvable ou inaccessible (%s)", username)
            raise exceptions.AuthenticationFailed("Identifiants incorrects")
        if not password:
                logger.warning("LoginSerializer.validate: mot de passe manquant pour %s", username)
                raise exceptions.AuthenticationFailed("Mot de passe obligatoire")
        if not user.check_password(password):
                logger.warning("LoginSerializer.validate: mot de passe incorrect pour %s", username)
                raise exceptions.AuthenticationFailed("Mot de passe incorrect")
        _ensure_account_usable(user)
        logger.debug("LoginSerializer.validate: authentification réussie pour %s", username)
        attrs['user'] = user
        return attrs

class LoginSerializerF2FA_STEP2(serializers.Serializer):
    username = serializers.CharField()
    code = serializers.CharField(required=True)
    
    def validate(self, attrs):
        
        """
        permet de verifier l'authentification
        """
        
        attrs = super().validate(attrs)
        
        username = attrs.get('username')
        code = attrs.get('code')

        logger.debug("LoginSerializerF2FA_STEP2.validate: tentative pour username=%s", username)

        try:
            user = User.get(username)
        except (User.DoesNotExist, PermissionError):
            logger.warning("LoginSerializerF2FA_STEP2.validate: utilisateur introuvable ou inaccessible (%s)", username)
            raise exceptions.AuthenticationFailed("Identifiants incorrects")

        if 'otp_secret' in forge_auth_config.optional_fields or not forge_auth_config.otp_conf.USE_OTP:
            logger.warning("LoginSerializerF2FA_STEP2.validate: OTP désactivé pour cette configuration, connexion refusée pour %s", username)
            raise exceptions.AuthenticationFailed("OTP désactivé pour cette configuration")

        if not code:
            logger.warning("LoginSerializerF2FA_STEP2.validate: code OTP manquant pour %s", username)
            raise exceptions.AuthenticationFailed("Code OTP obligatoire")
        try:
            otp_token = user.otp_token
        except OtpToken.DoesNotExist:
            logger.warning("LoginSerializerF2FA_STEP2.validate: aucun OTP demandé pour %s", username)
            raise exceptions.AuthenticationFailed("Aucun code OTP n'a été demandé")
        if not otp_token.verify_otp(code):
            logger.warning("LoginSerializerF2FA_STEP2.validate: code OTP incorrect pour %s", username)
            raise exceptions.AuthenticationFailed("Code incorrect")

        _ensure_account_usable(user)
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
        attrs['access'] = str(token.access_token)
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
            raise serializers.ValidationError("Mot de passe actuel incorrect")
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
            raise exceptions.AuthenticationFailed("Lien de réinitialisation invalide ou expiré")

        if not default_token_generator.check_token(user, token):
            logger.warning("ConfirmPasswordResetSerializer.validate: token invalide ou expiré pour %s", username)
            raise exceptions.AuthenticationFailed("Lien de réinitialisation invalide ou expiré")

        _run_password_validators(new_password, user=user)
        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.save(update_fields=['password'])
        logger.info("ConfirmPasswordResetSerializer: mot de passe réinitialisé pour %s", user)
        return user


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

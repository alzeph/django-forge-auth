import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from rest_framework import serializers, exceptions
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from forge_auth.conf import forge_auth_config
from forge_auth.models import OtpToken

logger = logging.getLogger(__name__)

User = get_user_model()


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

    def create(self, validated_data):
        with transaction.atomic():
            user = User.objects.create_user(**validated_data)
            logger.info("UserSerializer.create: nouvel utilisateur créé (%s)", user)
            return user
        
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
        except Exception as e:
            logger.warning("RefreshSerializer.validate: refresh token invalide : %s", e)
            raise
        attrs['access'] = str(token.access_token)
        logger.debug("RefreshSerializer.validate: access token régénéré")
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

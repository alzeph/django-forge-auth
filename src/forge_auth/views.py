import logging

from drf_spectacular.utils import extend_schema, OpenApiResponse
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.request import Request
from forge_auth.throttling import ForgeAuthScopedRateThrottle
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import viewsets, permissions, mixins, serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from forge_auth.serializers import (
    ApiKeySerializer, ConfirmContactVerificationSerializer,
    ConfirmPasswordResetSerializer, CreateApiKeySerializer,
    DetailResponseSerializer, ExistsResponseSerializer, GroupSerializer,
    LoginAuditLogSerializer, MAGIC_LINK_SALT,
    LoginSerializerF2FA_STEP1, LoginSerializerF2FA_STEP2, LoginSerializer,
    LoginSuccessSerializer, MagicLinkConfirmSerializer, MagicLinkRequestSerializer,
    RequestContactVerificationSerializer, RequestPasswordResetSerializer,
    RevokeApiKeySerializer, RevokeSessionSerializer, SessionSerializer,
    SocialLoginSerializer, TotpConfirmSerializer, TotpDisableSerializer,
    UserSerializer, UsernameSerializer, ValidationError400Serializer,
    VerifyFieldSerializer, ChangePasswordSerializer, RefreshSerializer,
    _ensure_account_usable,
)
from forge_auth.models import ApiKey, Group, LoginAuditLog, OtpToken, SessionMetadata, SocialAccount, TotpDevice
from forge_auth.conf import forge_auth_config
from forge_auth.permissions import IsSelfOrAdmin
from forge_auth.signals import (
    contact_verification_requested, magic_link_requested, otp_requested,
    password_reset_requested, user_logged_in,
)

logger = logging.getLogger(__name__)

User = get_user_model()


def _revoke_outstanding_tokens(user) -> None:
    """
    Blackliste tous les refresh tokens actifs de *user*.

    Utilisé après un changement ou une réinitialisation de mot de passe pour
    invalider les autres sessions ouvertes avec l'ancien mot de passe.
    No-op si `rest_framework_simplejwt.token_blacklist` n'est pas installé.
    """
    try:
        from rest_framework_simplejwt.token_blacklist.models import (
            BlacklistedToken, OutstandingToken,
        )
    except ImportError:
        logger.debug("_revoke_outstanding_tokens: token_blacklist non installé, rien à faire")
        return
    outstanding = OutstandingToken.objects.filter(user=user)
    count = 0
    for token in outstanding:
        _, created = BlacklistedToken.objects.get_or_create(token=token)
        count += int(created)
    logger.info("_revoke_outstanding_tokens: %d token(s) révoqué(s) pour user=%s", count, user)


def _record_session(request, user, token) -> None:
    """Crée/met à jour la SessionMetadata associée au refresh token émis lors d'une connexion."""
    SessionMetadata.objects.update_or_create(
        jti=token["jti"],
        defaults={
            "user": user,
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:255],
            "ip_address": request.META.get("REMOTE_ADDR"),
        },
    )


def _sync_session_on_refresh(serializer, request) -> None:
    """Fait suivre le jti d'une SessionMetadata existante quand `refresh` rotate le refresh token."""
    old_jti = getattr(serializer, "_old_jti", None)
    new_jti = getattr(serializer, "_new_jti", None)
    if not old_jti or not new_jti or old_jti == new_jti:
        return
    SessionMetadata.objects.filter(jti=old_jti).update(
        jti=new_jti,
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
        ip_address=request.META.get("REMOTE_ADDR"),
    )

class GroupViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet
):
    """
    ViewSet qui ne permet que GET (liste et détail) sur Group.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer 
    permission_classes = [permissions.AllowAny]
    pagination_class = None
    

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # Déclaré ici (None = pas de limite) pour que `@action(..., throttle_scope=...)`
    # puisse le surcharger par action : DRF exige que tout kwarg passé à
    # `@action` corresponde à un attribut déjà existant sur la classe.
    throttle_scope = None
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'post', 'patch', 'put', 'delete']

    def get_permissions(self):
        public_actions = [
            'create', 'obtain_otp', 'verify_email', 'verify_phone', 'login',
            'authenticate_user', 'verify_otp_and_login', 'refresh',
            'request_password_reset', 'confirm_password_reset',
            'request_magic_link', 'confirm_magic_link', 'social_login',
        ]
        if self.action in public_actions:
            permission_classes = [permissions.AllowAny]
        else:
            # IsSelfOrAdmin évite l'IDOR : sans elle, IsAuthenticated seul
            # permettrait à n'importe quel utilisateur connecté de
            # lire/modifier/supprimer n'importe quel autre utilisateur.
            permission_classes = [permissions.IsAuthenticated, IsSelfOrAdmin]
        return [permission() for permission in permission_classes]

    def destroy(self, request, *args, **kwargs):
        """
        Suppression d'un compte. Une auto-suppression (l'utilisateur
        supprime son propre compte) exige son mot de passe courant dans le
        corps de la requête (`{"password": "..."}`) : DELETE seul est trop
        facilement déclenchable par erreur ou via un token volé pour une
        action aussi irréversible. Le staff supprimant un tiers n'est pas
        concerné (déjà un mode de confiance différent).
        """
        instance = self.get_object()
        if instance.pk == request.user.pk:
            password = request.data.get('password')
            if not password or not request.user.check_password(password):
                logger.warning("destroy: confirmation de mot de passe manquante/incorrecte pour l'auto-suppression de %s", request.user)
                return Response(
                    {"detail": _("Mot de passe requis et correct pour supprimer votre propre compte.")},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        return super().destroy(request, *args, **kwargs)

    def _verify_field(self, field_name: str, value: str, exclude_value: str = None):
        """
        Méthode générique pour vérifier si une valeur existe sur un champ spécifique.
        """
        logger.debug("_verify_field: field=%s exclude=%s", field_name, bool(exclude_value))
        if not value:
            logger.warning("_verify_field: valeur manquante pour le champ %s", field_name)
            return Response({"detail": _("%(field)s is required") % {"field": field_name}}, status=status.HTTP_400_BAD_REQUEST)

        users_qs = User.objects.all()
        if exclude_value:
            users_qs = users_qs.exclude(**{field_name: exclude_value})

        exists = users_qs.filter(**{field_name: value}).exists()
        logger.debug("_verify_field: field=%s exists=%s", field_name, exists)
        return Response({"exists": exists})
    
    @extend_schema(
        operation_id="verify-email",
        summary="Vérifie si un email existe",
        description="Permet de vérifier si un email est déjà utilisé. Possibilité d'exclure un email existant.",
        request=VerifyFieldSerializer,
        responses={200: ExistsResponseSerializer}
    )
    @action(
        detail=False,
        methods=['post'],
        url_path=r'verify-email',
        url_name='verify-email',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_verify',
    )
    def verify_email(self, request: Request, pk=None):
        """
        Vérifie si un email existe, possibilité d'exclure un email.
        """
        logger.debug("verify_email appelé")
        verify_email = request.data.get('verify')
        exclude_email = request.data.get('exclude')
        return self._verify_field('email', verify_email, exclude_email)

    @extend_schema(
        operation_id='verify-phone_number',
        summary="Vérifie si un phone existe",
        description="Permet de vérifier si un phone est déjà utilisé. Possibilité d'exclure un phone existant.",
        request=VerifyFieldSerializer,
        responses={200: ExistsResponseSerializer}
    )
    @action(
        detail=False,
        methods=['post'],
        url_path=r'verify-phone',
        url_name='verify-phone',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_verify',
    )
    def verify_phone(self, request: Request, pk=None):
        """
        Vérifie si un numéro de téléphone existe, possibilité d'exclure un numéro.
        """
        logger.debug("verify_phone appelé")
        verify_phone = request.data.get('verify')
        exclude_phone = request.data.get('exclude')
        return self._verify_field('phone_number', verify_phone, exclude_phone)

    @extend_schema(
        methods=['get'],
        operation_id="get_current_user",
        summary="Get current user",
        description="Get current user",
        responses={200: UserSerializer},
        request=None
    )
    @action(
        detail=False,
        methods=['get'],
        url_name='current',
        url_path=r'current'
    )
    def current_user(self, request):
        logger.debug("current_user appelé par %s", request.user)
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @extend_schema(
        methods=['post'],
        operation_id="login",
        summary="Login",
        description="Login",
        request=LoginSerializer,
        responses={
            200: LoginSuccessSerializer,
            400: ValidationError400Serializer
        }
    )
    @action(
        detail=False, methods=['post'], url_name='login', url_path=r'login',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_login',
    )
    def login(self, request, *args, **kwargs):
        logger.debug("login: tentative avec username=%s", request.data.get('username'))
        serializer = LoginSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("login: échec d'authentification pour username=%s", request.data.get('username'))
            raise
        user = serializer.validated_data['user']
        token = RefreshToken.for_user(user)
        access = str(token.access_token)
        refresh = str(token)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        _record_session(request, user, token)

        logger.info("login: authentification réussie pour user=%s", user)
        user_logged_in.send(sender=self.__class__, request=request, user=user)

        response = Response(status=status.HTTP_200_OK)
        if forge_auth_config.jwt_conf.VIA_JSON:
            response.data = {"access": access, "refresh": refresh, "user": UserSerializer(user).data}
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            response.set_cookie(
                key="access",
                value=access,
                httponly=True,
                secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None,
                path="/",
            )

            response.set_cookie(
                key="refresh",
                value=refresh,
                httponly=True,
                secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None,
                path="/",
            )
        return response
        
    @extend_schema(
        methods=['post'],
        operation_id="logout",
        summary="Logout",
        description="Logout",
        responses={204: None}
    )
    @action(detail=False, methods=['post'], url_name='logout', url_path=r'logout')
    def logout(self, request, *args, **kwargs):
        logger.debug("logout appelé par %s", getattr(request, "user", None))
        try:
            refresh = request.COOKIES.get("refresh") or request.data.get("refresh")
            if refresh:
                token = RefreshToken(refresh)
                token.blacklist()
                logger.info("logout: refresh token blacklisté pour %s", getattr(request, "user", None))
                SessionMetadata.objects.filter(jti=token["jti"]).update(revoked_at=timezone.now())
        except Exception as e:
            logger.warning("logout: échec du blacklist du refresh token : %s", e)

        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        return response

    @extend_schema(
        methods=['get'],
        operation_id="session_check",
        summary="Check session",
        description="Check session",
        responses={200: UserSerializer}
    )
    @action(detail=False, methods=['get'], url_name='session-check', url_path=r'session-check')
    def session_check(self, request, *args, **kwargs):
        # Si on arrive ici, le user est authentifié
        logger.debug("session_check: session valide pour %s", request.user)
        return Response(UserSerializer(request.user).data)
    
    @extend_schema(
        methods=['post'],
        operation_id="refresh",
        summary="Refresh token",
        description="Refresh token",
        request=RefreshSerializer,
        responses={200: RefreshSerializer}
    )
    @action(
        detail=False, methods=['post'], url_name='refresh', url_path=r'refresh',
        # Public : c'est justement l'endpoint qu'on appelle quand l'access
        # token est expiré/absent, donc IsAuthenticated serait contradictoire
        # (voir aussi le renouvellement silencieux dans JWTAuthenticationFlexible).
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_refresh',
    )
    def refresh(self, request, *args, **kwargs):
        logger.debug("refresh: tentative de renouvellement de token")
        refresh = request.COOKIES.get("refresh") or request.data.get("refresh")
        serializer = RefreshSerializer(data={"refresh": refresh})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("refresh: token de rafraîchissement invalide")
            raise
        logger.info("refresh: nouveau token access généré")
        _sync_session_on_refresh(serializer, request)
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            # Sans ceci, le cookie "access" expiré n'était jamais remplacé :
            # le nouvel access token n'existait qu'en JSON, incohérent avec
            # un flux tout-en-cookie httponly.
            response.set_cookie(
                key="access",
                value=serializer.validated_data["access"],
                httponly=True,
                secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None,
                path="/",
            )
            if "refresh" in serializer.validated_data:
                # Rotation activée (JWT.ROTATE_REFRESH_TOKENS) : le cookie
                # "refresh" doit lui aussi être remplacé par le nouveau.
                response.set_cookie(
                    key="refresh",
                    value=serializer.validated_data["refresh"],
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite=settings.DEBUG and "Lax" or None,
                    path="/",
                )
        return response
    
    @extend_schema(
        operation_id="obtain-otp",
        summary="obtention de l'otp",
        description="obtention de l'otp de la part de l'utilisateur",
        request=UsernameSerializer,
        responses={
            200: OpenApiResponse(
                description="OTP envoyé",
                response=UserSerializer
            ),
            404: OpenApiResponse(
                description="User not found"
            ),
        },
    )
    @action(
        detail=False, methods=['post'], url_name='obtain-otp', url_path=r'obtain-otp',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_otp',
    )
    def obtain_otp(self, request, *args, **kwargs):
        logger.debug("obtain_otp: demande pour username=%s", request.data.get('username'))
        if "otp_secret" not in forge_auth_config.optional_fields and forge_auth_config.otp_conf.USE_OTP:
            data = UsernameSerializer(data=request.data)
            data.is_valid(raise_exception=True)
            try:
                user = User.get(data.validated_data["username"])
            except User.DoesNotExist:
                logger.warning("obtain_otp: utilisateur introuvable pour username=%s", data.validated_data.get("username"))
                return Response({"detail": _("User not found")}, status=status.HTTP_404_NOT_FOUND)
            except PermissionError as exc:
                logger.warning("obtain_otp: accès refusé pour username=%s : %s", data.validated_data.get("username"), exc)
                return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
            otp_token, created = OtpToken.objects.get_or_create(user=user)
            otp_token.generate_otp()
            logger.info(
                "obtain_otp: code OTP généré pour user=%s (jeton %s)",
                user, "créé" if created else "existant",
            )
            otp_requested.send(sender=self.__class__, request=request, user=user, otp_token=otp_token)
            return Response(UserSerializer(user).data)
        logger.debug("obtain_otp: OTP désactivé pour cette configuration")
        return Response({"detail": _("OTP désactivé pour cette configuration")}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    # webflow double authentification
    @extend_schema(
        operation_id="authenticate-user",
        summary="Authentification de l'utilisateur",
        description="Authentification de l'utilisateur avec avec son mot de passe",
        request=LoginSerializerF2FA_STEP1,
        responses={200: UserSerializer, 400: ValidationError400Serializer}
    )
    @action(
        detail=False, methods=['post'], url_name='authenticate-user', url_path=r'authenticate-user',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_login',
    )
    def authenticate_user(self, request, *args, **kwargs):
        logger.debug("authenticate_user: tentative pour username=%s", request.data.get('username'))
        serializer = LoginSerializerF2FA_STEP1(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("authenticate_user: échec d'authentification pour username=%s", request.data.get('username'))
            raise
        user = serializer.validated_data['user']
        logger.info("authenticate_user: authentification réussie pour user=%s", user)
        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)
    
    @extend_schema(
        operation_id="verify-otp-and-login",
        summary="Vérification du code OTP et connexion",
        description="Vérification du code OTP et connexion de l'utilisateur",
        request=LoginSerializerF2FA_STEP2,
        responses={200: UserSerializer, 400: ValidationError400Serializer}
    )
    @action(
        detail=False, methods=['post'], url_name='verify-otp-and-login', url_path=r'verify-otp-and-login',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_otp',
    )
    def verify_otp_and_login(self, request, *args, **kwargs):
        logger.debug("verify_otp_and_login: tentative pour username=%s", request.data.get('username'))
        serializer = LoginSerializerF2FA_STEP2(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("verify_otp_and_login: échec de vérification pour username=%s", request.data.get('username'))
            raise
        user = serializer.validated_data['user']
        token = RefreshToken.for_user(user)
        access = str(token.access_token)
        refresh = str(token)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        _record_session(request, user, token)

        logger.info("verify_otp_and_login: authentification réussie pour user=%s", user)
        user_logged_in.send(sender=self.__class__, request=request, user=user)

        response = Response(status=status.HTTP_200_OK)
        if forge_auth_config.jwt_conf.VIA_JSON:
            response.data = {"access": access, "refresh": refresh, "user": UserSerializer(user).data}
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            response.set_cookie(
                key="access",
                value=access,
                httponly=True,
                secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None,
                path="/",
            )

            response.set_cookie(
                key="refresh",
                value=refresh,
                httponly=True,
                secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None,
                path="/",
            )
        return response

    @extend_schema(
        operation_id="change-password",
        summary="Changer son mot de passe",
        description="Permet à l'utilisateur authentifié de changer son mot de passe (ancien mot de passe requis). Révoque les autres sessions (refresh tokens) si rest_framework_simplejwt.token_blacklist est installé.",
        request=ChangePasswordSerializer,
        responses={200: DetailResponseSerializer, 400: ValidationError400Serializer}
    )
    @action(detail=False, methods=['post'], url_name='change-password', url_path=r'change-password')
    def change_password(self, request, *args, **kwargs):
        logger.debug("change_password: tentative pour user=%s", request.user)
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("change_password: échec pour user=%s", request.user)
            raise
        serializer.save()
        _revoke_outstanding_tokens(request.user)
        logger.info("change_password: mot de passe changé pour user=%s", request.user)
        return Response({"detail": _("Mot de passe changé avec succès.")}, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="request-password-reset",
        summary="Demande de réinitialisation de mot de passe",
        description=(
            "Génère un token de réinitialisation et envoie le signal "
            "password_reset_requested (l'envoi effectif du lien/code par "
            "email/SMS est à la charge du projet hôte, voir la doc du signal)."
        ),
        request=RequestPasswordResetSerializer,
        responses={
            200: DetailResponseSerializer,
            404: OpenApiResponse(description="User not found"),
        },
    )
    @action(
        detail=False, methods=['post'], url_name='request-password-reset', url_path=r'request-password-reset',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_password_reset',
    )
    def request_password_reset(self, request, *args, **kwargs):
        logger.debug("request_password_reset: demande pour username=%s", request.data.get('username'))
        serializer = RequestPasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        try:
            user = User.get(username)
        except User.DoesNotExist:
            logger.warning("request_password_reset: utilisateur introuvable pour username=%s", username)
            return Response({"detail": _("User not found")}, status=status.HTTP_404_NOT_FOUND)
        except PermissionError as exc:
            logger.warning("request_password_reset: accès refusé pour username=%s : %s", username, exc)
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)

        token = default_token_generator.make_token(user)
        logger.info("request_password_reset: token généré pour user=%s", user)
        password_reset_requested.send(sender=self.__class__, request=request, user=user, token=token)
        return Response({"detail": _("Un token de réinitialisation a été généré.")}, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="confirm-password-reset",
        summary="Confirmation de réinitialisation de mot de passe",
        description="Vérifie le token émis par request-password-reset et applique le nouveau mot de passe.",
        request=ConfirmPasswordResetSerializer,
        responses={
            200: DetailResponseSerializer,
            401: OpenApiResponse(description="Token invalide ou expiré"),
        },
    )
    @action(
        detail=False, methods=['post'], url_name='confirm-password-reset', url_path=r'confirm-password-reset',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_password_reset',
    )
    def confirm_password_reset(self, request, *args, **kwargs):
        logger.debug("confirm_password_reset: tentative pour username=%s", request.data.get('username'))
        serializer = ConfirmPasswordResetSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("confirm_password_reset: échec pour username=%s", request.data.get('username'))
            raise
        user = serializer.save()
        _revoke_outstanding_tokens(user)
        logger.info("confirm_password_reset: mot de passe réinitialisé pour user=%s", user)
        return Response({"detail": _("Mot de passe réinitialisé avec succès.")}, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------
    # Vérification de contact (email / téléphone) par token
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="request-contact-verification",
        summary="Demande de vérification d'un champ de contact",
        description="Génère un token de vérification pour l'email ou le téléphone de l'utilisateur authentifié.",
        request=RequestContactVerificationSerializer,
        responses={200: DetailResponseSerializer, 400: ValidationError400Serializer},
    )
    @action(detail=False, methods=['post'], url_name='request-contact-verification', url_path=r'request-contact-verification')
    def request_contact_verification(self, request, *args, **kwargs):
        serializer = RequestContactVerificationSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        token = serializer.make_token()
        field = serializer.validated_data['field']
        logger.info("request_contact_verification: token généré pour %s (champ=%s)", request.user, field)
        contact_verification_requested.send(sender=self.__class__, request=request, user=request.user, field=field, token=token)
        return Response({"detail": _("Un token de vérification a été généré.")}, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="confirm-contact-verification",
        summary="Confirmation de vérification d'un champ de contact",
        description="Vérifie le token émis par request-contact-verification et marque le compte comme vérifié.",
        request=ConfirmContactVerificationSerializer,
        responses={200: DetailResponseSerializer, 401: OpenApiResponse(description="Token invalide ou expiré")},
    )
    @action(detail=False, methods=['post'], url_name='confirm-contact-verification', url_path=r'confirm-contact-verification')
    def confirm_contact_verification(self, request, *args, **kwargs):
        serializer = ConfirmContactVerificationSerializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("confirm_contact_verification: échec pour %s", request.user)
            raise
        serializer.save()
        return Response({"detail": _("Champ de contact vérifié avec succès.")}, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------
    # MFA TOTP applicatif (second facteur additionnel, indépendant de OTP)
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="mfa-totp-setup",
        summary="Démarre la configuration d'un second facteur TOTP",
        description="Crée (ou régénère) un secret TOTP non confirmé et renvoie l'URI de provisioning à encoder en QR code.",
        request=None,
        responses={200: OpenApiResponse(description="secret + provisioning_uri")},
    )
    @action(detail=False, methods=['post'], url_name='mfa-totp-setup', url_path=r'mfa-totp-setup')
    def mfa_totp_setup(self, request, *args, **kwargs):
        device, _created = TotpDevice.objects.update_or_create(
            user=request.user, defaults={"confirmed": False},
        )
        if _created is False:
            # On régénère un nouveau secret à chaque appel de setup tant que
            # le device n'est pas confirmé (évite de rester bloqué avec un
            # secret déjà scanné/perdu).
            device.secret = TotpDevice._meta.get_field("secret").default()
            device.save(update_fields=["secret"])
        logger.info("mfa_totp_setup: secret TOTP (re)généré pour %s", request.user)
        return Response(
            {"secret": device.secret, "provisioning_uri": device.provisioning_uri()},
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        operation_id="mfa-totp-confirm",
        summary="Confirme l'activation du second facteur TOTP",
        description="Vérifie un code généré par l'application d'authentification et active le second facteur. Renvoie les codes de secours (à afficher une seule fois).",
        request=TotpConfirmSerializer,
        responses={200: OpenApiResponse(description="backup_codes"), 400: ValidationError400Serializer},
    )
    @action(detail=False, methods=['post'], url_name='mfa-totp-confirm', url_path=r'mfa-totp-confirm')
    def mfa_totp_confirm(self, request, *args, **kwargs):
        serializer = TotpConfirmSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        device = request.user.totp_device
        device.confirmed = True
        device.save(update_fields=["confirmed"])
        backup_codes = device.generate_backup_codes()
        logger.info("mfa_totp_confirm: second facteur TOTP activé pour %s", request.user)
        return Response({"backup_codes": backup_codes}, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="mfa-totp-disable",
        summary="Désactive le second facteur TOTP",
        description="Supprime le device TOTP de l'utilisateur (mot de passe requis).",
        request=TotpDisableSerializer,
        responses={204: None, 400: ValidationError400Serializer},
    )
    @action(detail=False, methods=['post'], url_name='mfa-totp-disable', url_path=r'mfa-totp-disable')
    def mfa_totp_disable(self, request, *args, **kwargs):
        serializer = TotpDisableSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        TotpDevice.objects.filter(user=request.user).delete()
        logger.info("mfa_totp_disable: second facteur TOTP désactivé pour %s", request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Connexion sans mot de passe (magic link)
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="request-magic-link",
        summary="Demande un lien de connexion sans mot de passe",
        description="Actif uniquement si FORGE_AUTH['MAGIC_LINK']['ENABLED'] est True.",
        request=MagicLinkRequestSerializer,
        responses={200: DetailResponseSerializer, 404: OpenApiResponse(description="User not found"), 405: OpenApiResponse(description="Magic link désactivé")},
    )
    @action(
        detail=False, methods=['post'], url_name='request-magic-link', url_path=r'request-magic-link',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_login',
    )
    def request_magic_link(self, request, *args, **kwargs):
        if not forge_auth_config.magic_link_conf.ENABLED:
            logger.debug("request_magic_link: fonctionnalité désactivée (MAGIC_LINK.ENABLED=False)")
            return Response({"detail": _("Connexion sans mot de passe désactivée pour cette configuration")}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        serializer = MagicLinkRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = User.get(serializer.validated_data['username'])
        except User.DoesNotExist:
            logger.warning("request_magic_link: utilisateur introuvable pour username=%s", serializer.validated_data.get('username'))
            return Response({"detail": _("User not found")}, status=status.HTTP_404_NOT_FOUND)
        except PermissionError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        token = signing.dumps({"pk": user.pk}, salt=MAGIC_LINK_SALT)
        logger.info("request_magic_link: token généré pour user=%s", user)
        magic_link_requested.send(sender=self.__class__, request=request, user=user, token=token)
        return Response({"detail": _("Un lien de connexion a été généré.")}, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="confirm-magic-link",
        summary="Confirme un lien de connexion sans mot de passe",
        description="Vérifie le token émis par request-magic-link et délivre un JWT, comme un login classique.",
        request=MagicLinkConfirmSerializer,
        responses={200: LoginSuccessSerializer, 401: OpenApiResponse(description="Lien invalide ou expiré")},
    )
    @action(
        detail=False, methods=['post'], url_name='confirm-magic-link', url_path=r'confirm-magic-link',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_login',
    )
    def confirm_magic_link(self, request, *args, **kwargs):
        if not forge_auth_config.magic_link_conf.ENABLED:
            return Response({"detail": _("Connexion sans mot de passe désactivée pour cette configuration")}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
        serializer = MagicLinkConfirmSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("confirm_magic_link: échec de vérification du token")
            raise
        user = serializer.validated_data['user']
        token = RefreshToken.for_user(user)
        access = str(token.access_token)
        refresh = str(token)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        _record_session(request, user, token)

        logger.info("confirm_magic_link: authentification réussie pour user=%s", user)
        user_logged_in.send(sender=self.__class__, request=request, user=user)

        response = Response(status=status.HTTP_200_OK)
        if forge_auth_config.jwt_conf.VIA_JSON:
            response.data = {"access": access, "refresh": refresh, "user": UserSerializer(user).data}
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            response.set_cookie(
                key="access", value=access, httponly=True, secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None, path="/",
            )
            response.set_cookie(
                key="refresh", value=refresh, httponly=True, secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None, path="/",
            )
        return response

    # ------------------------------------------------------------------
    # Gestion des sessions/appareils
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="sessions",
        summary="Liste les sessions actives",
        description="Liste les refresh tokens émis (non révoqués) pour l'utilisateur authentifié : appareil/IP/dernière activité.",
        responses={200: SessionSerializer(many=True)},
    )
    @action(detail=False, methods=['get'], url_name='sessions', url_path=r'sessions')
    def sessions(self, request, *args, **kwargs):
        queryset = SessionMetadata.objects.filter(user=request.user, revoked_at__isnull=True)
        return Response(SessionSerializer(queryset, many=True).data)

    @extend_schema(
        operation_id="revoke-session",
        summary="Révoque une session précise",
        description="Blackliste le refresh token de la session ciblée (voir aussi change-password, qui révoque tout).",
        request=RevokeSessionSerializer,
        responses={204: None, 404: OpenApiResponse(description="Session introuvable")},
    )
    @action(detail=False, methods=['post'], url_name='revoke-session', url_path=r'revoke-session')
    def revoke_session(self, request, *args, **kwargs):
        serializer = RevokeSessionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            session = SessionMetadata.objects.get(pk=serializer.validated_data['session_id'], user=request.user)
        except SessionMetadata.DoesNotExist:
            return Response({"detail": _("Session introuvable")}, status=status.HTTP_404_NOT_FOUND)
        session.revoke()
        logger.info("revoke_session: session %s révoquée par %s", session.pk, request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Historique de connexion
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="login-history",
        summary="Historique de connexion",
        description="Liste les 50 dernières tentatives de connexion (réussies ou non) de l'utilisateur authentifié.",
        responses={200: LoginAuditLogSerializer(many=True)},
    )
    @action(detail=False, methods=['get'], url_name='login-history', url_path=r'login-history')
    def login_history(self, request, *args, **kwargs):
        queryset = LoginAuditLog.objects.filter(user=request.user)[:50]
        return Response(LoginAuditLogSerializer(queryset, many=True).data)

    # ------------------------------------------------------------------
    # Clés API (authentification machine-à-machine)
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="api-keys",
        summary="Liste mes clés API",
        description="Liste les clés API de l'utilisateur authentifié (la clé en clair n'est jamais renvoyée après sa création).",
        responses={200: ApiKeySerializer(many=True)},
    )
    @action(detail=False, methods=['get'], url_name='api-keys', url_path=r'api-keys')
    def api_keys(self, request, *args, **kwargs):
        queryset = ApiKey.objects.filter(user=request.user)
        return Response(ApiKeySerializer(queryset, many=True).data)

    @extend_schema(
        operation_id="create-api-key",
        summary="Crée une clé API",
        description="La clé en clair n'est renvoyée qu'une seule fois, à cet instant : elle n'est jamais stockée (seul son hash l'est).",
        request=CreateApiKeySerializer,
        responses={201: OpenApiResponse(description="key + ApiKeySerializer")},
    )
    @action(detail=False, methods=['post'], url_name='create-api-key', url_path=r'create-api-key')
    def create_api_key(self, request, *args, **kwargs):
        serializer = CreateApiKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        raw_key, prefix, hashed_key = ApiKey.generate_key()
        api_key = ApiKey.objects.create(
            user=request.user, name=serializer.validated_data['name'], prefix=prefix, hashed_key=hashed_key,
        )
        logger.info("create_api_key: clé '%s' créée pour %s", api_key.name, request.user)
        data = ApiKeySerializer(api_key).data
        data['key'] = raw_key
        return Response(data, status=status.HTTP_201_CREATED)

    @extend_schema(
        operation_id="revoke-api-key",
        summary="Révoque une clé API",
        request=RevokeApiKeySerializer,
        responses={204: None, 404: OpenApiResponse(description="Clé introuvable")},
    )
    @action(detail=False, methods=['post'], url_name='revoke-api-key', url_path=r'revoke-api-key')
    def revoke_api_key(self, request, *args, **kwargs):
        serializer = RevokeApiKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            api_key = ApiKey.objects.get(pk=serializer.validated_data['key_id'], user=request.user)
        except ApiKey.DoesNotExist:
            return Response({"detail": _("Clé introuvable")}, status=status.HTTP_404_NOT_FOUND)
        api_key.revoke()
        logger.info("revoke_api_key: clé '%s' révoquée par %s", api_key.name, request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Connexion sociale (OIDC générique)
    # ------------------------------------------------------------------

    @extend_schema(
        operation_id="social-login",
        summary="Connexion via un fournisseur OIDC (Google, Microsoft...)",
        description="Vérifie l'id_token auprès du fournisseur configuré dans FORGE_AUTH['SOCIAL_AUTH'], lie/crée le compte, puis délivre un JWT.",
        request=SocialLoginSerializer,
        responses={200: LoginSuccessSerializer, 401: OpenApiResponse(description="id_token invalide")},
    )
    @action(
        detail=False, methods=['post'], url_name='social-login', url_path=r'social-login',
        permission_classes=[permissions.AllowAny],
        throttle_classes=[ForgeAuthScopedRateThrottle], throttle_scope='forge_auth_login',
    )
    def social_login(self, request, *args, **kwargs):
        serializer = SocialLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            logger.warning("social_login: échec de vérification pour provider=%s", request.data.get('provider'))
            raise
        provider = serializer.validated_data['provider']
        claims = serializer.validated_data['claims']
        subject = claims['sub']
        email = claims.get('email', '')

        social_account = SocialAccount.objects.filter(provider=provider, subject=subject).select_related('user').first()
        if social_account:
            user = social_account.user
        else:
            username_field = forge_auth_config.get_username_field()
            if username_field != "email" or not email:
                logger.error(
                    "social_login: impossible de créer un compte pour provider=%s (USERNAME_FIELD=%s, email fourni=%s)",
                    provider, username_field, bool(email),
                )
                return Response(
                    {"detail": "Impossible de créer un compte à partir de ce fournisseur avec cette configuration."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user, _created = User.objects.get_or_create(email=email)
            SocialAccount.objects.create(user=user, provider=provider, subject=subject, email=email)
            logger.info("social_login: nouveau compte lié pour provider=%s (%s)", provider, email)

        try:
            _ensure_account_usable(user)
        except exceptions.AuthenticationFailed as exc:
            return Response({"detail": str(exc.detail)}, status=status.HTTP_401_UNAUTHORIZED)

        token = RefreshToken.for_user(user)
        access = str(token.access_token)
        refresh = str(token)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        _record_session(request, user, token)

        logger.info("social_login: authentification réussie pour user=%s via provider=%s", user, provider)
        user_logged_in.send(sender=self.__class__, request=request, user=user)

        response = Response(status=status.HTTP_200_OK)
        if forge_auth_config.jwt_conf.VIA_JSON:
            response.data = {"access": access, "refresh": refresh, "user": UserSerializer(user).data}
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            response.set_cookie(
                key="access", value=access, httponly=True, secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None, path="/",
            )
            response.set_cookie(
                key="refresh", value=refresh, httponly=True, secure=not settings.DEBUG,
                samesite=settings.DEBUG and "Lax" or None, path="/",
            )
        return response

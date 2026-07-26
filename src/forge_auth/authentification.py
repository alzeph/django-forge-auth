import logging

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from forge_auth.conf import forge_auth_config

logger = logging.getLogger(__name__)


class JWTAuthenticationFlexible(JWTAuthentication):

    def authenticate(self, request):
        raw_token = None
        source = None
        # 1. Essaye de lire depuis le cookie
        if forge_auth_config.jwt_conf.VIA_HTTP_ONLY:
            raw_token = request.COOKIES.get("access")
            if raw_token:
                source = "cookie"

        # 2. essaye de lire depuis le header
        if forge_auth_config.jwt_conf.VIA_JSON:
            if not raw_token:
                auth_header = request.headers.get("Authorization")
                if auth_header and auth_header.startswith("Bearer "):
                    raw_token = auth_header.split(" ")[1]
                    source = "header"

        # 3. Aucun token trouvé
        if not raw_token:
            logger.debug("JWTAuthenticationFlexible.authenticate: aucun token trouvé")
            return None

        # 4. Valide le token, avec renouvellement automatique via le refresh token si besoin
        try:
            validated_token = self.get_validated_token(raw_token)
        except (InvalidToken, TokenError) as e:
            new_access = self._try_silent_refresh(request, source, e)
            if not new_access:
                raise
            raw_token = new_access
            validated_token = self.get_validated_token(raw_token)

        # 5. Retourne l'utilisateur et le token
        user = self.get_user(validated_token)
        logger.debug("JWTAuthenticationFlexible.authenticate: authentifié via %s pour user=%s", source, user)
        return user, validated_token

    def _try_silent_refresh(self, request, source, original_error):
        # Évite d'obliger un client (ou un job automatisé) à appeler /refresh
        # explicitement : tant que le refresh token est valide, l'access token
        # expiré est régénéré à la volée pour cette requête.
        refresh_raw = request.COOKIES.get("refresh")
        if not refresh_raw and forge_auth_config.jwt_conf.VIA_JSON:
            data = getattr(request, "data", None)
            if data:
                refresh_raw = data.get("refresh")

        if not refresh_raw:
            logger.warning(
                "JWTAuthenticationFlexible.authenticate: token invalide (source=%s) et aucun refresh disponible : %s",
                source, original_error,
            )
            return None

        try:
            new_access = str(RefreshToken(refresh_raw).access_token)
        except TokenError as e:
            logger.warning(
                "JWTAuthenticationFlexible.authenticate: échec du renouvellement automatique (source=%s) : %s",
                source, e,
            )
            return None

        logger.info("JWTAuthenticationFlexible.authenticate: access token renouvelé automatiquement (source=%s)", source)
        return new_access

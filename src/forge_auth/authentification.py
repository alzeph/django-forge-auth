import logging

from rest_framework_simplejwt.authentication import JWTAuthentication
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

        # 4. Valide le token
        try:
            validated_token = self.get_validated_token(raw_token)
        except Exception as e:
            logger.warning("JWTAuthenticationFlexible.authenticate: token invalide (source=%s) : %s", source, e)
            raise

        # 5. Retourne l'utilisateur et le token
        user = self.get_user(validated_token)
        logger.debug("JWTAuthenticationFlexible.authenticate: authentifié via %s pour user=%s", source, user)
        return user, validated_token

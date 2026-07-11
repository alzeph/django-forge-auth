import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q
from forge_auth.conf import forge_auth_config

logger = logging.getLogger(__name__)

User = get_user_model()

class MultiFieldBackend(ModelBackend):
    """
    Permet à l'utilisateur de se connecter avec un ou plusieurs champs 
    définis comme identifiants de connexion (ex: email, phone_number, username).
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            return None

        logger.debug("MultiFieldBackend.authenticate: tentative pour username=%s", username)

        # Récupération des champs de login depuis la configuration Forge
        main_field = forge_auth_config.get("USERNAME_FIELD")
        alt_fields = forge_auth_config.get("ALTERNATIVE_USERNAME_FIELDS") or []

        # On regroupe tous les champs dans une liste unique
        login_fields = [main_field] + list(alt_fields)

        # Construction dynamique de la requête Q
        query = Q()
        for field in login_fields:
            if not field:
                continue
            # Utilisation de __iexact pour éviter les problèmes de casse (majuscules/minuscules)
            query |= Q(**{f"{field}__iexact": username})

        try:
            # Exécution de la recherche avec la requête dynamique
            user = User.objects.get(query)
        except User.DoesNotExist:
            logger.debug("MultiFieldBackend.authenticate: aucun utilisateur pour username=%s", username)
            return None
        except User.MultipleObjectsReturned:
            # Sécurité si plusieurs utilisateurs partagent par erreur le même identifiant
            logger.error("MultiFieldBackend.authenticate: plusieurs utilisateurs correspondent à username=%s", username)
            return None

        # Vérification du mot de passe via la méthode native de Django
        if user.check_password(password) and self.user_can_authenticate(user):
            logger.info("MultiFieldBackend.authenticate: authentification réussie pour user=%s", user)
            return user

        logger.warning("MultiFieldBackend.authenticate: mot de passe incorrect ou compte inactif pour username=%s", username)
        return None

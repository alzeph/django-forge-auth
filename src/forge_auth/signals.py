from django.dispatch import Signal, receiver
from django.db.models.signals import post_migrate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from forge_auth.conf import forge_auth_config
import logging

logger = logging.getLogger(__name__)


User = get_user_model()

user_logged_in = Signal()
"""
Envoyé par ``UserViewSet.login`` juste après une authentification réussie
(mot de passe ou OTP selon la config), avant que la réponse ne soit
renvoyée au client. Permet au projet hôte de brancher des actions
personnalisées (audit, notifications, mise à jour de métadonnées, etc.)
sans surcharger la vue.

Arguments envoyés : ``sender`` (la classe ``UserViewSet``), ``request``,
``user``.

Utilisation côté projet hôte :

    from django.dispatch import receiver
    from forge_auth.signals import user_logged_in

    @receiver(user_logged_in)
    def on_forge_auth_login(sender, request, user, **kwargs):
        ...
"""

otp_requested = Signal()
"""
Envoyé par ``UserViewSet.obtain_otp`` juste après la génération d'un
nouveau code OTP, avant que la réponse ne soit renvoyée au client.
C'est le point d'extension prévu pour l'envoi effectif du code (SMS,
WhatsApp, email...) — voir la section "Points non automatisés" du
README : ``OTP.OTP_CANAL`` n'est qu'une métadonnée de configuration,
l'envoi réel est à la charge du projet hôte.

Arguments envoyés : ``sender`` (la classe ``UserViewSet``), ``request``,
``user``, ``otp_token`` (le code en clair est disponible via
``otp_token.otp_code``).

Utilisation côté projet hôte :

    from django.dispatch import receiver
    from forge_auth.signals import otp_requested

    @receiver(otp_requested)
    def on_forge_auth_otp_requested(sender, request, user, otp_token, **kwargs):
        send_sms(user.phone_number, otp_token.otp_code)
"""


@receiver(post_migrate)
def create_superuser(sender, **kwargs):
    username_field = forge_auth_config.get_username_field()
    credentials = forge_auth_config.get("CREDENTIALS_SUPERUSER")
    if not User.objects.filter(is_superuser=True).exists():
        try:
            data = {
                username_field: credentials.get('username'),
                "password": credentials.get('password'),
                "last_name":"Admin",
                "first_name":"Auth default",
            }
        except AttributeError:
            logger.error("CREDENTIALS_SUPERUSER non configuré correctement")
            data = {
                username_field: credentials.username,
                "password": credentials.password,
                "last_name":"Admin",
                "first_name":"Auth default",
            }
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des credentials superuser : {e}")
            return
        try:
            user = User.objects.create_superuser(**data)
            logger.info(f"Super utilisateur créé avec success : {user}") 
        except Exception as e:
            logger.error(f"Super utilisateur par default non créé : {e}")

@receiver(post_migrate)
def initialize_groups(sender, **kwargs):
    group_create = []
    for group_name in forge_auth_config.get("GROUPS"):
        _, created = Group.objects.get_or_create(name=group_name)
        if created:
            group_create.append(group_name)
    if group_create:
        logger.info(f"Groupes crées avec success : {group_create}")


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


password_reset_requested = Signal()
"""
Envoyé par ``UserViewSet.request_password_reset`` juste après la génération
d'un token de réinitialisation de mot de passe, avant que la réponse ne soit
renvoyée au client. C'est le point d'extension prévu pour l'envoi effectif du
lien/code de réinitialisation (email, SMS...) — même principe que
``otp_requested``, voir la section "Points non automatisés" du README.

Arguments envoyés : ``sender`` (la classe ``UserViewSet``), ``request``,
``user``, ``token`` (le token en clair, à inclure dans le lien envoyé à
l'utilisateur — il est vérifié par ``UserViewSet.confirm_password_reset``).

Utilisation côté projet hôte :

    from django.dispatch import receiver
    from forge_auth.signals import password_reset_requested

    @receiver(password_reset_requested)
    def on_forge_auth_password_reset_requested(sender, request, user, token, **kwargs):
        send_email(user.email, f"https://example.com/reset?username={user.username}&token={token}")
"""


contact_verification_requested = Signal()
"""
Envoyé par ``UserViewSet.request_contact_verification`` juste après la
génération d'un token de vérification pour un champ de contact (email ou
téléphone), avant que la réponse ne soit renvoyée au client. Même principe
que ``otp_requested``/``password_reset_requested`` : rien n'envoie le lien
par défaut, c'est le point d'extension prévu pour ça.

Arguments envoyés : ``sender`` (la classe ``UserViewSet``), ``request``,
``user``, ``field`` (``"email"`` ou ``"phone_number"``), ``token``.

Utilisation côté projet hôte :

    from django.dispatch import receiver
    from forge_auth.signals import contact_verification_requested

    @receiver(contact_verification_requested)
    def on_forge_auth_contact_verification_requested(sender, request, user, field, token, **kwargs):
        if field == "email":
            send_email(user.email, f"https://example.com/verify-email?token={token}")
        else:
            send_sms(user.phone_number, f"Code de vérification : {token}")
"""


magic_link_requested = Signal()
"""
Envoyé par ``UserViewSet.request_magic_link`` juste après la génération d'un
token de connexion sans mot de passe, avant que la réponse ne soit renvoyée
au client. Actif uniquement si ``FORGE_AUTH["MAGIC_LINK"]["ENABLED"]`` est
``True``. Rien n'envoie le lien par défaut, c'est le point d'extension prévu
pour ça (même principe que ``otp_requested``).

Arguments envoyés : ``sender`` (la classe ``UserViewSet``), ``request``,
``user``, ``token``.

Utilisation côté projet hôte :

    from django.dispatch import receiver
    from forge_auth.signals import magic_link_requested

    @receiver(magic_link_requested)
    def on_forge_auth_magic_link_requested(sender, request, user, token, **kwargs):
        send_email(user.email, f"https://example.com/magic-login?token={token}")
"""


@receiver(post_migrate)
def create_superuser(sender, **kwargs):
    logger.debug("create_superuser: signal post_migrate reçu (sender=%s)", sender)
    username_field = forge_auth_config.get_username_field()
    credentials = forge_auth_config.get("CREDENTIALS_SUPERUSER")
    if not User.objects.filter(is_superuser=True).exists():
        # `credentials` est toujours une instance de CredentialSuperuserConf
        # (voir ForgeAuthConfig._merge_conf) : jamais un dict, donc pas de
        # `.get()` à tenter ici.
        data = {
            username_field: credentials.username,
            "password": credentials.password,
            "last_name": "Admin",
            "first_name": "Auth default",
        }
        try:
            user = User.objects.create_superuser(**data)
            logger.info(f"Super utilisateur créé avec success : {user}")
        except Exception as e:
            logger.error(f"Super utilisateur par default non créé : {e}")
    else:
        logger.debug("create_superuser: un superutilisateur existe déjà, rien à faire")

@receiver(post_migrate)
def initialize_groups(sender, **kwargs):
    logger.debug("initialize_groups: signal post_migrate reçu (sender=%s)", sender)
    group_create = []
    for group_name in forge_auth_config.get("GROUPS"):
        _, created = Group.objects.get_or_create(name=group_name)
        if created:
            group_create.append(group_name)
    if group_create:
        logger.info(f"Groupes crées avec success : {group_create}")
    else:
        logger.debug("initialize_groups: aucun nouveau groupe à créer")


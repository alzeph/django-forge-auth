from django.dispatch import receiver
from django.db.models.signals import post_migrate
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from forge_auth.conf import forge_auth_config
import logging

logger = logging.getLogger(__name__)


User = get_user_model()


@receiver(post_migrate)
def create_superuser(sender, **kwargs):
    username_field = forge_auth_config.get_username_field()
    credentials = forge_auth_config.get("CREDENTIALS_SUPERUSER")
    if not User.objects.filter(is_superuser=True).exists():
        data = {
            username_field: credentials["username"],
            "password": credentials["password"],
            "last_name":"Admin",
            "first_name":"Auth default",
        }
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
        logger.info(f"Groupes crées avec success : ", {group_create})


from django.apps import AppConfig


class ForgeAuthConfig(AppConfig):
    name = 'forge_auth'

    def ready(self):
        from forge_auth.conf import forge_auth_config
        forge_auth_config.validate()

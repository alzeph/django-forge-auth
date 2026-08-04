"""
Régression : les messages d'erreur de serializers.py/views.py sont passés
dans gettext_lazy (`_`). Un piège classique de cet alias est qu'assigner une
variable nommée `_` n'importe où dans une fonction qui appelle aussi `_(...)`
la transforme en variable locale non initialisée au moment de l'appel
(`UnboundLocalError`) — repéré sur `UsernameSerializer.validate_username`
(`_, created = User.objects.get_or_create(...)` shadowait le `_` de
traduction). Ce test active la traduction (`django.utils.translation.
activate`) et exerce plusieurs chemins d'erreur pour s'assurer qu'aucun
autre appel à `_(...)` n'est cassé de la même façon.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import translation
from rest_framework.test import APIClient

User = get_user_model()


class TranslationDoesNotCrashTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        translation.activate("fr")
        self.addCleanup(translation.deactivate)

    def test_obtain_otp_with_register_include_in_otp(self):
        from forge_auth.conf import forge_auth_config

        # `register_include_in_otp` est matérialisé une seule fois au
        # démarrage (voir CLAUDE.md) : `override_settings` + `reset()` ne
        # suffit pas, il faut muter directement l'attribut vivant, comme
        # `tests/_helpers.py::temporarily_disable_otp` le fait pour otp_conf.
        original = forge_auth_config.register_include_in_otp
        forge_auth_config.register_include_in_otp = True
        try:
            response = self.client.post(
                reverse("forge_auth:users-obtain-otp"), {"username": "+225000001400"}, format="json"
            )
        finally:
            forge_auth_config.register_include_in_otp = original
        self.assertEqual(response.status_code, 200)

    def test_obtain_otp_unknown_username_returns_400_not_500(self):
        response = self.client.post(
            reverse("forge_auth:users-obtain-otp"), {"username": "+225000001401"}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_login_missing_data_returns_400_not_500(self):
        response = self.client.post(reverse("forge_auth:users-login"), {}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_verify_field_missing_value_returns_400_not_500(self):
        response = self.client.post(reverse("forge_auth:users-verify-email"), {}, format="json")
        self.assertEqual(response.status_code, 400)

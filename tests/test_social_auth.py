"""
Tests de la connexion sociale OIDC générique :
src/forge_auth/serializers.py::SocialLoginSerializer,
src/forge_auth/views.py::social_login,
src/forge_auth/models.py::SocialAccount.

`forge_auth.social.verify_id_token` fait un appel réseau réel (découverte
OIDC + JWKS) : on le mocke systématiquement ici, comme documenté dans
social.py — ce n'est pas le rôle d'une suite de tests unitaires de taper un
vrai fournisseur OAuth.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.models import SocialAccount
from tests._helpers import forge_auth_override

User = get_user_model()

GOOGLE_CONF = {"google": {"ISSUER": "https://accounts.google.com", "CLIENT_ID": "test-client-id"}}


class SocialLoginTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("forge_auth:users-social-login")

    @patch("forge_auth.social.verify_id_token")
    def test_unconfigured_provider_is_rejected(self, mock_verify):
        response = self.client.post(self.url, {"provider": "google", "id_token": "whatever"}, format="json")
        self.assertEqual(response.status_code, 400)
        mock_verify.assert_not_called()

    @patch("forge_auth.social.verify_id_token")
    def test_invalid_id_token_is_rejected(self, mock_verify):
        mock_verify.side_effect = Exception("signature invalide")
        with forge_auth_override(USERNAME_FIELD="email", SOCIAL_AUTH=GOOGLE_CONF):
            response = self.client.post(self.url, {"provider": "google", "id_token": "bad"}, format="json")
        self.assertEqual(response.status_code, 401)

    @patch("forge_auth.social.verify_id_token")
    def test_creates_account_on_first_login(self, mock_verify):
        mock_verify.return_value = {"sub": "goog-123", "email": "alice@example.com"}
        with forge_auth_override(USERNAME_FIELD="email", SOCIAL_AUTH=GOOGLE_CONF):
            response = self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertEqual(response.data["user"]["email"], "alice@example.com")
        self.assertTrue(User.objects.filter(email="alice@example.com").exists())
        self.assertTrue(SocialAccount.objects.filter(provider="google", subject="goog-123").exists())

    @patch("forge_auth.social.verify_id_token")
    def test_reuses_existing_account_on_subsequent_login(self, mock_verify):
        mock_verify.return_value = {"sub": "goog-456", "email": "bob@example.com"}
        with forge_auth_override(USERNAME_FIELD="email", SOCIAL_AUTH=GOOGLE_CONF):
            first = self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")
            second = self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")

        self.assertEqual(first.data["user"]["pk"], second.data["user"]["pk"])
        self.assertEqual(User.objects.filter(email="bob@example.com").count(), 1)
        self.assertEqual(SocialAccount.objects.filter(provider="google", subject="goog-456").count(), 1)

    @patch("forge_auth.social.verify_id_token")
    def test_missing_sub_claim_is_rejected(self, mock_verify):
        mock_verify.return_value = {"email": "no-sub@example.com"}
        with forge_auth_override(USERNAME_FIELD="email", SOCIAL_AUTH=GOOGLE_CONF):
            response = self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")
        self.assertEqual(response.status_code, 401)

    @patch("forge_auth.social.verify_id_token")
    def test_rejects_login_for_suspended_linked_account(self, mock_verify):
        mock_verify.return_value = {"sub": "goog-789", "email": "carol@example.com"}
        with forge_auth_override(USERNAME_FIELD="email", SOCIAL_AUTH=GOOGLE_CONF):
            self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")
            user = User.objects.get(email="carol@example.com")
            user.mark_as_suspended()

            response = self.client.post(self.url, {"provider": "google", "id_token": "good"}, format="json")
        self.assertEqual(response.status_code, 401)

    def test_does_not_require_authentication(self):
        # Provider non configuré par défaut : 400 (pas d'id_token à vérifier),
        # et surtout pas bloqué en amont par IsAuthenticated.
        response = self.client.post(self.url, {"provider": "google", "id_token": "whatever"}, format="json")
        self.assertEqual(response.status_code, 400)

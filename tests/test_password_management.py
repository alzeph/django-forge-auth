"""
Tests des nouveaux endpoints de gestion du mot de passe
(src/forge_auth/views.py) :

- `users/change-password/` : changement de mot de passe par un utilisateur
  déjà authentifié (ancien mot de passe requis).
- `users/request-password-reset/` + `users/confirm-password-reset/` : flux
  "mot de passe oublié", basé sur `django.contrib.auth.tokens.
  default_token_generator` (stateless, pas de migration nécessaire) et sur
  le signal `forge_auth.signals.password_reset_requested` (envoi effectif
  du token à la charge du projet hôte, même principe que `otp_requested`).
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.signals import password_reset_requested

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class ChangePasswordTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000300", password="OldPassw0rd!")
        self.url = reverse("forge_auth:users-change-password")

    def test_change_password_success(self):
        response = _client_for(self.user).post(
            self.url, {"old_password": "OldPassw0rd!", "new_password": "N3wPassw0rd!"}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("N3wPassw0rd!"))
        self.assertFalse(self.user.check_password("OldPassw0rd!"))

    def test_wrong_old_password_is_rejected(self):
        response = _client_for(self.user).post(
            self.url, {"old_password": "wrong", "new_password": "N3wPassw0rd!"}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OldPassw0rd!"))

    def test_weak_new_password_is_rejected(self):
        response = _client_for(self.user).post(
            self.url, {"old_password": "OldPassw0rd!", "new_password": "1234"}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_requires_authentication(self):
        response = APIClient().post(
            self.url, {"old_password": "OldPassw0rd!", "new_password": "N3wPassw0rd!"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_revokes_outstanding_refresh_tokens(self):
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

        refresh = RefreshToken.for_user(self.user)
        self.assertFalse(BlacklistedToken.objects.filter(token__jti=refresh["jti"]).exists())

        response = _client_for(self.user).post(
            self.url, {"old_password": "OldPassw0rd!", "new_password": "N3wPassw0rd!"}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            OutstandingToken.objects.filter(jti=refresh["jti"]).exists()
            and BlacklistedToken.objects.filter(token__jti=refresh["jti"]).exists()
        )


class RequestPasswordResetTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000301", password="qwerty123")
        self.url = reverse("forge_auth:users-request-password-reset")

    def test_generates_token_and_sends_signal(self):
        calls = []

        def recorder(sender, **kwargs):
            calls.append(kwargs)

        password_reset_requested.connect(recorder)
        try:
            response = self.client.post(self.url, {"username": self.user.username}, format="json")
        finally:
            password_reset_requested.disconnect(recorder)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["user"], self.user)
        self.assertTrue(default_token_generator.check_token(self.user, calls[0]["token"]))

    def test_unknown_username_returns_404(self):
        response = self.client.post(self.url, {"username": "+225000000999"}, format="json")
        self.assertEqual(response.status_code, 404)

    def test_does_not_require_authentication(self):
        response = self.client.post(self.url, {"username": self.user.username}, format="json")
        self.assertNotEqual(response.status_code, 401)


class ConfirmPasswordResetTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000302", password="OldPassw0rd!")
        self.url = reverse("forge_auth:users-confirm-password-reset")

    def _valid_token(self):
        return default_token_generator.make_token(self.user)

    def test_confirm_with_valid_token_changes_password(self):
        token = self._valid_token()
        response = self.client.post(
            self.url,
            {"username": self.user.username, "token": token, "new_password": "N3wPassw0rd!"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("N3wPassw0rd!"))

    def test_confirm_with_invalid_token_is_rejected(self):
        response = self.client.post(
            self.url,
            {"username": self.user.username, "token": "not-a-valid-token", "new_password": "N3wPassw0rd!"},
            format="json",
        )
        self.assertEqual(response.status_code, 401)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OldPassw0rd!"))

    def test_token_is_single_use(self):
        """Le token est lié au hash du mot de passe (via default_token_generator) :
        une fois le mot de passe changé, le même token redevient invalide."""
        token = self._valid_token()
        first = self.client.post(
            self.url,
            {"username": self.user.username, "token": token, "new_password": "N3wPassw0rd!"},
            format="json",
        )
        self.assertEqual(first.status_code, 200)

        second = self.client.post(
            self.url,
            {"username": self.user.username, "token": token, "new_password": "AnotherPassw0rd!"},
            format="json",
        )
        self.assertEqual(second.status_code, 401)

    def test_weak_new_password_is_rejected(self):
        token = self._valid_token()
        response = self.client.post(
            self.url,
            {"username": self.user.username, "token": token, "new_password": "1234"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("OldPassw0rd!"))

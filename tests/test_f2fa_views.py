"""
Tests du flux de double authentification (F2FA) : UserViewSet.authenticate_user
et UserViewSet.verify_otp_and_login (src/forge_auth/views.py), et des
serializers associés (src/forge_auth/serializers.py).

Couvre deux régressions :
- authenticate_user/verify_otp_and_login doivent être accessibles anonymement
  (get_permissions() doit les lister dans public_actions, sinon impossible de
  se connecter sans être déjà authentifié).
- verify_otp_and_login ne doit jamais délivrer de JWT sans vérifier un code
  OTP valide, y compris quand OTP est désactivé en configuration (avant fix :
  aucune vérification n'était faite dans ce cas, permettant de se connecter
  comme n'importe quel utilisateur avec juste son username).
"""
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.models import OtpToken
from tests._helpers import temporarily_disable_otp

User = get_user_model()


@override_settings(DEBUG=False)
class AuthenticateUserTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000070", password="qwerty123")
        self.url = reverse("forge_auth:users-authenticate-user")

    def test_allows_anonymous_access_with_correct_credentials(self):
        response = self.client.post(
            self.url, {"username": self.user.username, "password": "qwerty123"}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["pk"], self.user.pk)

    def test_wrong_password_is_rejected(self):
        response = self.client.post(
            self.url, {"username": self.user.username, "password": "wrong-password"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_unknown_user_is_rejected(self):
        response = self.client.post(
            self.url, {"username": "+225000000099", "password": "qwerty123"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_password_returns_400(self):
        response = self.client.post(self.url, {"username": self.user.username}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_does_not_issue_tokens(self):
        response = self.client.post(
            self.url, {"username": self.user.username, "password": "qwerty123"}, format="json"
        )
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)


@override_settings(DEBUG=False)
class VerifyOtpAndLoginTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000071", password="qwerty123")
        self.url = reverse("forge_auth:users-verify-otp-and-login")

    def _request_otp(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp()
        return code

    def test_allows_anonymous_access_and_issues_tokens_with_correct_code(self):
        code = self._request_otp()
        response = self.client.post(
            self.url, {"username": self.user.username, "code": code}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertEqual(response.data["user"]["pk"], self.user.pk)
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_login)

    def test_wrong_code_is_rejected(self):
        self._request_otp()
        response = self.client.post(
            self.url, {"username": self.user.username, "code": "0000"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_code_returns_400(self):
        response = self.client.post(self.url, {"username": self.user.username}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_unknown_user_is_rejected(self):
        response = self.client.post(
            self.url, {"username": "+225000000098", "code": "1234"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_no_otp_requested_is_rejected(self):
        response = self.client.post(
            self.url, {"username": self.user.username, "code": "1234"}, format="json"
        )
        self.assertEqual(response.status_code, 401)

    def test_fails_closed_when_otp_disabled(self):
        """
        Régression : avant le fix, désactiver OTP en config faisait sauter
        toute vérification dans LoginSerializerF2FA_STEP2, et un simple
        username suffisait à obtenir un JWT valide.
        """
        code = self._request_otp()
        with temporarily_disable_otp():
            response = self.client.post(
                self.url, {"username": self.user.username, "code": code}, format="json"
            )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.data)

    def test_username_alone_never_grants_tokens_when_otp_disabled(self):
        with temporarily_disable_otp():
            response = self.client.post(self.url, {"username": self.user.username}, format="json")
        self.assertIn(response.status_code, (400, 401))

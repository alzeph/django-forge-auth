"""
Tests du MFA TOTP applicatif (src/forge_auth/models.py::TotpDevice,
src/forge_auth/views.py::mfa_totp_setup/mfa_totp_confirm/mfa_totp_disable),
et de son intégration dans le login (src/forge_auth/serializers.py::
_verify_totp_if_enabled), second facteur indépendant de l'OTP SMS/WhatsApp
qui sert de méthode de connexion principale.
"""
import pyotp
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.models import TotpDevice
from tests._helpers import temporarily_disable_otp

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class TotpSetupConfirmDisableTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000600", password="qwerty123")
        self.client_auth = _client_for(self.user)

    def test_setup_returns_provisioning_uri_and_secret(self):
        response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-setup"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("secret", response.data)
        self.assertIn("provisioning_uri", response.data)
        self.assertTrue(TotpDevice.objects.filter(user=self.user, confirmed=False).exists())

    def test_setup_requires_authentication(self):
        response = APIClient().post(reverse("forge_auth:users-mfa-totp-setup"))
        self.assertEqual(response.status_code, 401)

    def test_confirm_with_valid_code_activates_and_returns_backup_codes(self):
        setup_response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-setup"))
        secret = setup_response.data["secret"]
        code = pyotp.TOTP(secret).now()

        response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-confirm"), {"code": code}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("backup_codes", response.data)
        self.assertEqual(len(response.data["backup_codes"]), 10)
        self.user.totp_device.refresh_from_db()
        self.assertTrue(self.user.totp_device.confirmed)

    def test_confirm_with_invalid_code_is_rejected(self):
        self.client_auth.post(reverse("forge_auth:users-mfa-totp-setup"))
        response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-confirm"), {"code": "000000"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_confirm_without_setup_is_rejected(self):
        response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-confirm"), {"code": "123456"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_disable_requires_correct_password(self):
        setup_response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-setup"))
        code = pyotp.TOTP(setup_response.data["secret"]).now()
        self.client_auth.post(reverse("forge_auth:users-mfa-totp-confirm"), {"code": code}, format="json")

        wrong = self.client_auth.post(reverse("forge_auth:users-mfa-totp-disable"), {"password": "wrong"}, format="json")
        self.assertEqual(wrong.status_code, 400)
        self.assertTrue(TotpDevice.objects.filter(user=self.user).exists())

        response = self.client_auth.post(reverse("forge_auth:users-mfa-totp-disable"), {"password": "qwerty123"}, format="json")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(TotpDevice.objects.filter(user=self.user).exists())


class TotpLoginIntegrationTestCase(TestCase):
    """L'ajout d'un second facteur TOTP confirmé doit bloquer le login sans ce facteur."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000601", password="qwerty123")
        auth_client = _client_for(self.user)
        setup_response = auth_client.post(reverse("forge_auth:users-mfa-totp-setup"))
        self.secret = setup_response.data["secret"]
        code = pyotp.TOTP(self.secret).now()
        confirm_response = auth_client.post(reverse("forge_auth:users-mfa-totp-confirm"), {"code": code}, format="json")
        self.backup_codes = confirm_response.data["backup_codes"]

    def test_login_without_totp_code_is_rejected(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123"},
                format="json",
            )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.data)

    def test_login_with_valid_totp_code_succeeds(self):
        code = pyotp.TOTP(self.secret).now()
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123", "totp_code": code},
                format="json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)

    def test_login_with_invalid_totp_code_is_rejected(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123", "totp_code": "000000"},
                format="json",
            )
        self.assertEqual(response.status_code, 401)

    def test_login_with_backup_code_succeeds_once(self):
        backup_code = self.backup_codes[0]
        with temporarily_disable_otp():
            first = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123", "backup_code": backup_code},
                format="json",
            )
            self.assertEqual(first.status_code, 200)

            second = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123", "backup_code": backup_code},
                format="json",
            )
        self.assertEqual(second.status_code, 401)

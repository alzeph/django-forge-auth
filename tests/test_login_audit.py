"""
Tests de l'historique de connexion :
src/forge_auth/models.py::LoginAuditLog,
src/forge_auth/serializers.py::_log_login_attempt,
src/forge_auth/views.py::login_history.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.models import LoginAuditLog
from tests._helpers import temporarily_disable_otp

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class LoginAuditLogWritingTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000001200", password="qwerty123")
        self.login_url = reverse("forge_auth:users-login")

    def test_successful_login_is_logged(self):
        with temporarily_disable_otp():
            self.client.post(self.login_url, {"username": self.user.username, "password": "qwerty123"}, format="json")
        entry = LoginAuditLog.objects.get(user=self.user)
        self.assertEqual(entry.result, LoginAuditLog.Result.SUCCESS)

    def test_wrong_password_is_logged_as_failure(self):
        with temporarily_disable_otp():
            self.client.post(self.login_url, {"username": self.user.username, "password": "wrong"}, format="json")
        entry = LoginAuditLog.objects.get(user=self.user)
        self.assertEqual(entry.result, LoginAuditLog.Result.FAILURE)
        self.assertEqual(entry.reason, "invalid_password")

    def test_unknown_username_is_logged_without_user(self):
        with temporarily_disable_otp():
            self.client.post(self.login_url, {"username": "+225000009999", "password": "whatever"}, format="json")
        entry = LoginAuditLog.objects.get(username_attempted="+225000009999")
        self.assertIsNone(entry.user)
        self.assertEqual(entry.result, LoginAuditLog.Result.FAILURE)
        self.assertEqual(entry.reason, "unknown_user")

    def test_disabled_account_login_is_logged_as_account_unusable(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        with temporarily_disable_otp():
            self.client.post(self.login_url, {"username": self.user.username, "password": "qwerty123"}, format="json")
        entry = LoginAuditLog.objects.get(user=self.user)
        self.assertEqual(entry.result, LoginAuditLog.Result.FAILURE)
        self.assertEqual(entry.reason, "account_unusable")

    def test_records_ip_and_user_agent(self):
        with temporarily_disable_otp():
            self.client.post(
                self.login_url,
                {"username": self.user.username, "password": "qwerty123"},
                format="json",
                HTTP_USER_AGENT="pytest-agent/1.0",
                REMOTE_ADDR="203.0.113.5",
            )
        entry = LoginAuditLog.objects.get(user=self.user)
        self.assertEqual(entry.user_agent, "pytest-agent/1.0")
        self.assertEqual(entry.ip_address, "203.0.113.5")


class LoginHistoryEndpointTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000001201", password="qwerty123")
        self.other = User.objects.create_user(phone_number="+225000001202", password="qwerty123")
        self.login_url = reverse("forge_auth:users-login")

    def test_requires_authentication(self):
        response = APIClient().get(reverse("forge_auth:users-login-history"))
        self.assertEqual(response.status_code, 401)

    def test_lists_only_own_history(self):
        with temporarily_disable_otp():
            self.client.post(self.login_url, {"username": self.user.username, "password": "wrong"}, format="json")
            self.client.post(self.login_url, {"username": self.other.username, "password": "wrong"}, format="json")

        response = _client_for(self.user).get(reverse("forge_auth:users-login-history"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

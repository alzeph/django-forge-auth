"""
Tests de la gestion des sessions/appareils :
src/forge_auth/models.py::SessionMetadata,
src/forge_auth/views.py::sessions/revoke_session,
et l'enregistrement automatique à la connexion (_record_session) /
la révocation au logout.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.models import SessionMetadata
from tests._helpers import temporarily_disable_otp

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class SessionRecordingTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000800", password="qwerty123")

    def test_login_records_a_session(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123"},
                format="json",
                HTTP_USER_AGENT="pytest-client/1.0",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(SessionMetadata.objects.filter(user=self.user).count(), 1)
        session = SessionMetadata.objects.get(user=self.user)
        self.assertEqual(session.user_agent, "pytest-client/1.0")
        self.assertFalse(session.is_revoked)

    def test_logout_revokes_the_session(self):
        with temporarily_disable_otp():
            login_response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123"},
                format="json",
            )
        access = login_response.data["access"]
        refresh = login_response.data["refresh"]
        auth_client = APIClient()
        auth_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

        logout_response = auth_client.post(reverse("forge_auth:users-logout"), {"refresh": refresh}, format="json")
        self.assertEqual(logout_response.status_code, 204)
        session = SessionMetadata.objects.get(user=self.user)
        self.assertTrue(session.is_revoked)


class SessionsListAndRevokeTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000801", password="qwerty123")
        self.other = User.objects.create_user(phone_number="+225000000802", password="qwerty123")
        self.auth_client = _client_for(self.user)

    def _login_session(self, user_agent="device-a"):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": self.user.username, "password": "qwerty123"},
                format="json",
                HTTP_USER_AGENT=user_agent,
            )
        return response

    def test_lists_only_own_active_sessions(self):
        self._login_session("device-a")
        self._login_session("device-b")
        # Session d'un autre utilisateur, ne doit pas apparaître.
        other_client = APIClient()
        with temporarily_disable_otp():
            other_client.post(
                reverse("forge_auth:users-login"),
                {"username": self.other.username, "password": "qwerty123"},
                format="json",
            )

        response = self.auth_client.get(reverse("forge_auth:users-sessions"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)
        user_agents = {s["user_agent"] for s in response.data}
        self.assertEqual(user_agents, {"device-a", "device-b"})

    def test_requires_authentication(self):
        response = APIClient().get(reverse("forge_auth:users-sessions"))
        self.assertEqual(response.status_code, 401)

    def test_revoke_own_session(self):
        self._login_session("device-a")
        session = SessionMetadata.objects.get(user=self.user)

        response = self.auth_client.post(
            reverse("forge_auth:users-revoke-session"), {"session_id": session.pk}, format="json"
        )
        self.assertEqual(response.status_code, 204)
        session.refresh_from_db()
        self.assertTrue(session.is_revoked)

    def test_cannot_revoke_another_users_session(self):
        other_client = APIClient()
        with temporarily_disable_otp():
            other_client.post(
                reverse("forge_auth:users-login"),
                {"username": self.other.username, "password": "qwerty123"},
                format="json",
            )
        other_session = SessionMetadata.objects.get(user=self.other)

        response = self.auth_client.post(
            reverse("forge_auth:users-revoke-session"), {"session_id": other_session.pk}, format="json"
        )
        self.assertEqual(response.status_code, 404)
        other_session.refresh_from_db()
        self.assertFalse(other_session.is_revoked)

    def test_revoke_unknown_session_returns_404(self):
        response = self.auth_client.post(
            reverse("forge_auth:users-revoke-session"), {"session_id": 999999}, format="json"
        )
        self.assertEqual(response.status_code, 404)

    def test_revoked_session_blacklists_refresh_token(self):
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

        login_response = self._login_session("device-a")
        session = SessionMetadata.objects.get(user=self.user)

        self.auth_client.post(reverse("forge_auth:users-revoke-session"), {"session_id": session.pk}, format="json")

        refresh_response = self.client.post(
            reverse("forge_auth:users-refresh"), {"refresh": login_response.data["refresh"]}, format="json"
        )
        self.assertEqual(refresh_response.status_code, 401)
        self.assertTrue(BlacklistedToken.objects.filter(token__jti=session.jti).exists())

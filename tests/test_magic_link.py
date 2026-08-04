"""
Tests du login sans mot de passe (magic link) :
src/forge_auth/views.py::request_magic_link/confirm_magic_link,
src/forge_auth/serializers.py::MagicLinkConfirmSerializer.

Désactivé par défaut (FORGE_AUTH["MAGIC_LINK"]["ENABLED"] = False) : les
tests mutent directement `forge_auth_config.magic_link_conf.ENABLED` (même
piège que otp_conf/jwt_conf, voir tests/_helpers.py).
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.core import signing
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.conf import forge_auth_config
from forge_auth.serializers import MAGIC_LINK_SALT
from forge_auth.signals import magic_link_requested

User = get_user_model()


@contextmanager
def magic_link_enabled(enabled=True):
    conf = forge_auth_config.magic_link_conf
    original = conf.ENABLED
    conf.ENABLED = enabled
    try:
        yield
    finally:
        conf.ENABLED = original


class RequestMagicLinkTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000700", password="qwerty123")

    def test_disabled_by_default(self):
        response = self.client.post(
            reverse("forge_auth:users-request-magic-link"), {"username": self.user.username}, format="json"
        )
        self.assertEqual(response.status_code, 405)

    def test_generates_token_and_sends_signal_when_enabled(self):
        calls = []

        def recorder(sender, **kwargs):
            calls.append(kwargs)

        magic_link_requested.connect(recorder)
        try:
            with magic_link_enabled():
                response = self.client.post(
                    reverse("forge_auth:users-request-magic-link"), {"username": self.user.username}, format="json"
                )
        finally:
            magic_link_requested.disconnect(recorder)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["user"], self.user)
        payload = signing.loads(calls[0]["token"], salt=MAGIC_LINK_SALT)
        self.assertEqual(payload["pk"], self.user.pk)

    def test_unknown_user_returns_404(self):
        with magic_link_enabled():
            response = self.client.post(
                reverse("forge_auth:users-request-magic-link"), {"username": "+225000000999"}, format="json"
            )
        self.assertEqual(response.status_code, 404)


class ConfirmMagicLinkTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000701", password="qwerty123")

    def _token(self):
        return signing.dumps({"pk": self.user.pk}, salt=MAGIC_LINK_SALT)

    def test_confirm_disabled_by_default(self):
        response = self.client.post(
            reverse("forge_auth:users-confirm-magic-link"), {"token": self._token()}, format="json"
        )
        self.assertEqual(response.status_code, 405)

    def test_confirm_with_valid_token_issues_jwt(self):
        with magic_link_enabled():
            response = self.client.post(
                reverse("forge_auth:users-confirm-magic-link"), {"token": self._token()}, format="json"
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertEqual(response.data["user"]["pk"], self.user.pk)

    def test_confirm_with_invalid_token_is_rejected(self):
        with magic_link_enabled():
            response = self.client.post(
                reverse("forge_auth:users-confirm-magic-link"), {"token": "not-a-token"}, format="json"
            )
        self.assertEqual(response.status_code, 401)

    def test_confirm_with_tampered_pk_is_rejected(self):
        token = signing.dumps({"pk": 9999999}, salt=MAGIC_LINK_SALT)
        with magic_link_enabled():
            response = self.client.post(
                reverse("forge_auth:users-confirm-magic-link"), {"token": token}, format="json"
            )
        self.assertEqual(response.status_code, 401)

    def test_confirm_rejects_suspended_account(self):
        self.user.mark_as_suspended()
        with magic_link_enabled():
            response = self.client.post(
                reverse("forge_auth:users-confirm-magic-link"), {"token": self._token()}, format="json"
            )
        self.assertEqual(response.status_code, 401)

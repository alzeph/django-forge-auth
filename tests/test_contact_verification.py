"""
Tests de la vérification de contact (email/téléphone) par token :
src/forge_auth/views.py::request_contact_verification/confirm_contact_verification,
src/forge_auth/serializers.py::RequestContactVerificationSerializer/
ConfirmContactVerificationSerializer.
"""
from django.contrib.auth import get_user_model
from django.core import signing
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.models import StatusMixin
from forge_auth.serializers import CONTACT_VERIFICATION_SALT
from forge_auth.signals import contact_verification_requested

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class RequestContactVerificationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            phone_number="+225000001000", email="alice@example.com", password="qwerty123"
        )
        self.client_auth = _client_for(self.user)

    def test_generates_token_and_sends_signal(self):
        calls = []

        def recorder(sender, **kwargs):
            calls.append(kwargs)

        contact_verification_requested.connect(recorder)
        try:
            response = self.client_auth.post(
                reverse("forge_auth:users-request-contact-verification"), {"field": "email"}, format="json"
            )
        finally:
            contact_verification_requested.disconnect(recorder)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["field"], "email")
        payload = signing.loads(calls[0]["token"], salt=CONTACT_VERIFICATION_SALT)
        self.assertEqual(payload["value"], "alice@example.com")

    def test_rejects_empty_field(self):
        user = User.objects.create_user(phone_number="+225000001001", password="qwerty123")
        client = _client_for(user)
        response = client.post(
            reverse("forge_auth:users-request-contact-verification"), {"field": "email"}, format="json"
        )
        self.assertEqual(response.status_code, 400)

    def test_requires_authentication(self):
        response = APIClient().post(
            reverse("forge_auth:users-request-contact-verification"), {"field": "email"}, format="json"
        )
        self.assertEqual(response.status_code, 401)


class ConfirmContactVerificationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            phone_number="+225000001002", email="bob@example.com", password="qwerty123"
        )
        self.client_auth = _client_for(self.user)

    def _generate_token(self, field="email"):
        calls = []

        def recorder(sender, **kwargs):
            calls.append(kwargs["token"])

        contact_verification_requested.connect(recorder)
        try:
            self.client_auth.post(
                reverse("forge_auth:users-request-contact-verification"), {"field": field}, format="json"
            )
        finally:
            contact_verification_requested.disconnect(recorder)
        return calls[0]

    def test_confirm_marks_account_verified(self):
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.UNVERIFIED)
        token = self._generate_token("email")

        response = self.client_auth.post(
            reverse("forge_auth:users-confirm-contact-verification"),
            {"field": "email", "token": token},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.VERIFIED)

    def test_confirm_with_invalid_token_is_rejected(self):
        response = self.client_auth.post(
            reverse("forge_auth:users-confirm-contact-verification"),
            {"field": "email", "token": "not-a-token"},
            format="json",
        )
        self.assertEqual(response.status_code, 401)

    def test_confirm_with_mismatched_field_is_rejected(self):
        token = self._generate_token("email")
        response = self.client_auth.post(
            reverse("forge_auth:users-confirm-contact-verification"),
            {"field": "phone_number", "token": token},
            format="json",
        )
        self.assertEqual(response.status_code, 401)

    def test_confirm_invalidated_when_value_changes(self):
        token = self._generate_token("email")
        self.user.email = "changed@example.com"
        self.user.save(update_fields=["email"])

        response = self.client_auth.post(
            reverse("forge_auth:users-confirm-contact-verification"),
            {"field": "email", "token": token},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_confirm_cannot_be_used_by_another_user(self):
        token = self._generate_token("email")
        other = User.objects.create_user(phone_number="+225000001003", email="other@example.com", password="qwerty123")
        other_client = _client_for(other)

        response = other_client.post(
            reverse("forge_auth:users-confirm-contact-verification"),
            {"field": "email", "token": token},
            format="json",
        )
        self.assertEqual(response.status_code, 401)

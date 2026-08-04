"""
Tests des clés API M2M :
src/forge_auth/models.py::ApiKey,
src/forge_auth/authentification.py::ApiKeyAuthentication,
src/forge_auth/views.py::create_api_key/api_keys/revoke_api_key.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.models import ApiKey

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class CreateListRevokeApiKeyTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000900", password="qwerty123")
        self.other = User.objects.create_user(phone_number="+225000000901", password="qwerty123")
        self.auth_client = _client_for(self.user)

    def test_create_returns_raw_key_once(self):
        response = self.auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "CI"}, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertIn("key", response.data)
        self.assertEqual(response.data["name"], "CI")
        api_key = ApiKey.objects.get(user=self.user)
        self.assertTrue(api_key.verify_key(response.data["key"]))

    def test_list_does_not_expose_raw_key_or_hash(self):
        self.auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "CI"}, format="json")
        response = self.auth_client.get(reverse("forge_auth:users-api-keys"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertNotIn("key", response.data[0])
        self.assertNotIn("hashed_key", response.data[0])

    def test_list_only_shows_own_keys(self):
        self.auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "mine"}, format="json")
        other_client = _client_for(self.other)
        other_client.post(reverse("forge_auth:users-create-api-key"), {"name": "not-mine"}, format="json")

        response = self.auth_client.get(reverse("forge_auth:users-api-keys"))
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["name"], "mine")

    def test_revoke_own_key(self):
        create_response = self.auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "CI"}, format="json")
        key_id = create_response.data["pk"]

        response = self.auth_client.post(reverse("forge_auth:users-revoke-api-key"), {"key_id": key_id}, format="json")
        self.assertEqual(response.status_code, 204)
        self.assertTrue(ApiKey.objects.get(pk=key_id).is_revoked)

    def test_cannot_revoke_another_users_key(self):
        create_response = self.auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "CI"}, format="json")
        key_id = create_response.data["pk"]
        other_client = _client_for(self.other)

        response = other_client.post(reverse("forge_auth:users-revoke-api-key"), {"key_id": key_id}, format="json")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(ApiKey.objects.get(pk=key_id).is_revoked)


class ApiKeyAuthenticationTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000902", password="qwerty123")
        auth_client = _client_for(self.user)
        create_response = auth_client.post(reverse("forge_auth:users-create-api-key"), {"name": "CI"}, format="json")
        self.raw_key = create_response.data["key"]
        self.key_id = create_response.data["pk"]

    def test_authenticates_with_valid_key(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Api-Key {self.raw_key}")
        response = client.get(reverse("forge_auth:users-current"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["pk"], self.user.pk)

    def test_rejects_invalid_key(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Api-Key not-a-real-key")
        response = client.get(reverse("forge_auth:users-current"))
        self.assertEqual(response.status_code, 401)

    def test_rejects_revoked_key(self):
        auth_client = _client_for(self.user)
        auth_client.post(reverse("forge_auth:users-revoke-api-key"), {"key_id": self.key_id}, format="json")

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Api-Key {self.raw_key}")
        response = client.get(reverse("forge_auth:users-current"))
        self.assertEqual(response.status_code, 401)

    def test_updates_last_used_at(self):
        api_key = ApiKey.objects.get(pk=self.key_id)
        self.assertIsNone(api_key.last_used_at)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Api-Key {self.raw_key}")
        client.get(reverse("forge_auth:users-current"))

        api_key.refresh_from_db()
        self.assertIsNotNone(api_key.last_used_at)

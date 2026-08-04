"""
Tests de UserViewSet.refresh (src/forge_auth/views.py).

Deux régressions couvertes :
- `refresh` exigeait IsAuthenticated, ce qui est contradictoire avec son
  propre but : c'est justement l'endpoint qu'on appelle quand l'access
  token est expiré ou absent. Il doit être accessible anonymement (la
  sécurité vient de la validité du refresh token lui-même, pas d'un token
  d'accès préalable).
- En mode JWT.VIA_HTTP_ONLY, le nouvel access token n'était renvoyé qu'en
  JSON : le cookie "access" existant (expiré) n'était jamais remplacé.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.conf import forge_auth_config

User = get_user_model()


@contextmanager
def jwt_modes(via_json=None, via_http_only=None, rotate_refresh_tokens=None):
    jwt_conf = forge_auth_config.jwt_conf
    original_json, original_cookie, original_rotate = (
        jwt_conf.VIA_JSON, jwt_conf.VIA_HTTP_ONLY, jwt_conf.ROTATE_REFRESH_TOKENS,
    )
    if via_json is not None:
        jwt_conf.VIA_JSON = via_json
    if via_http_only is not None:
        jwt_conf.VIA_HTTP_ONLY = via_http_only
    if rotate_refresh_tokens is not None:
        jwt_conf.ROTATE_REFRESH_TOKENS = rotate_refresh_tokens
    try:
        yield
    finally:
        jwt_conf.VIA_JSON, jwt_conf.VIA_HTTP_ONLY, jwt_conf.ROTATE_REFRESH_TOKENS = (
            original_json, original_cookie, original_rotate,
        )


class RefreshIsPublicTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000500", password="qwerty123")
        self.url = reverse("forge_auth:users-refresh")

    def test_refresh_works_without_any_authentication_header(self):
        refresh = RefreshToken.for_user(self.user)
        response = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)

    def test_refresh_rejects_invalid_refresh_token(self):
        response = self.client.post(self.url, {"refresh": "not-a-token"}, format="json")
        self.assertEqual(response.status_code, 401)


class RefreshCookieSyncTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000501", password="qwerty123")
        self.url = reverse("forge_auth:users-refresh")

    def test_updates_access_cookie_when_via_http_only(self):
        refresh = RefreshToken.for_user(self.user)
        with jwt_modes(via_http_only=True):
            self.client.cookies["refresh"] = str(refresh)
            response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.cookies)
        self.assertEqual(response.cookies["access"].value, response.data["access"])

    def test_no_access_cookie_set_when_via_http_only_disabled(self):
        refresh = RefreshToken.for_user(self.user)
        with jwt_modes(via_http_only=False):
            response = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("access", response.cookies)


class RefreshRotationTestCase(TestCase):
    """FORGE_AUTH["JWT"]["ROTATE_REFRESH_TOKENS"] : désactivé par défaut."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000502", password="qwerty123")
        self.url = reverse("forge_auth:users-refresh")

    def test_disabled_by_default_reuses_same_refresh_token(self):
        # `refresh` est renvoyé tel quel dans le corps (champ non write_only,
        # voir RefreshSerializer) même sans rotation : ce test vérifie que
        # sa valeur ne change PAS, pas son absence.
        refresh = RefreshToken.for_user(self.user)
        response = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["refresh"], str(refresh))

    def test_rotation_returns_new_refresh_token_and_blacklists_old_one(self):
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

        refresh = RefreshToken.for_user(self.user)
        old_jti = refresh["jti"]
        with jwt_modes(rotate_refresh_tokens=True):
            response = self.client.post(self.url, {"refresh": str(refresh)}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("refresh", response.data)
        self.assertNotEqual(response.data["refresh"], str(refresh))
        self.assertTrue(BlacklistedToken.objects.filter(token__jti=old_jti).exists())

    def test_rotated_old_refresh_token_can_no_longer_be_used(self):
        refresh = RefreshToken.for_user(self.user)
        with jwt_modes(rotate_refresh_tokens=True):
            first = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
            self.assertEqual(first.status_code, 200)

            second = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
        self.assertEqual(second.status_code, 401)

    def test_rotated_new_refresh_token_works(self):
        refresh = RefreshToken.for_user(self.user)
        with jwt_modes(rotate_refresh_tokens=True):
            first = self.client.post(self.url, {"refresh": str(refresh)}, format="json")
            new_refresh = first.data["refresh"]
            second = self.client.post(self.url, {"refresh": new_refresh}, format="json")
        self.assertEqual(second.status_code, 200)

    def test_rotation_updates_refresh_cookie_when_via_http_only(self):
        refresh = RefreshToken.for_user(self.user)
        with jwt_modes(via_http_only=True, rotate_refresh_tokens=True):
            self.client.cookies["refresh"] = str(refresh)
            response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("refresh", response.cookies)
        self.assertEqual(response.cookies["refresh"].value, response.data["refresh"])

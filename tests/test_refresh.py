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
def jwt_modes(via_json=None, via_http_only=None):
    jwt_conf = forge_auth_config.jwt_conf
    original_json, original_cookie = jwt_conf.VIA_JSON, jwt_conf.VIA_HTTP_ONLY
    if via_json is not None:
        jwt_conf.VIA_JSON = via_json
    if via_http_only is not None:
        jwt_conf.VIA_HTTP_ONLY = via_http_only
    try:
        yield
    finally:
        jwt_conf.VIA_JSON, jwt_conf.VIA_HTTP_ONLY = original_json, original_cookie


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

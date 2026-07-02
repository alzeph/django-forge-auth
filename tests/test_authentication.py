"""
Tests de JWTAuthenticationFlexible (src/forge_auth/authentification.py).

JWT.VIA_JSON / JWT.VIA_HTTP_ONLY sont lus via forge_auth_config.jwt_conf,
un attribut figé au démarrage (voir tests/_helpers.py) : on le mute donc
directement plutôt que de passer par override_settings(FORGE_AUTH=...).
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from forge_auth.authentification import JWTAuthenticationFlexible
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


class JWTAuthenticationFlexibleTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(phone_number="+225000000060", password="qwerty123")
        self.access_token = str(RefreshToken.for_user(self.user).access_token)
        self.auth = JWTAuthenticationFlexible()

    def test_no_token_returns_none(self):
        request = self.factory.get("/")
        self.assertIsNone(self.auth.authenticate(request))

    def test_authenticates_via_header_when_via_json_enabled(self):
        with jwt_modes(via_json=True, via_http_only=False):
            request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
            user, token = self.auth.authenticate(request)
        self.assertEqual(user, self.user)

    def test_header_ignored_when_via_json_disabled(self):
        with jwt_modes(via_json=False, via_http_only=False):
            request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
            self.assertIsNone(self.auth.authenticate(request))

    def test_authenticates_via_cookie_when_via_http_only_enabled(self):
        with jwt_modes(via_json=False, via_http_only=True):
            request = self.factory.get("/")
            request.COOKIES["access"] = self.access_token
            user, token = self.auth.authenticate(request)
        self.assertEqual(user, self.user)

    def test_cookie_ignored_when_via_http_only_disabled(self):
        with jwt_modes(via_json=False, via_http_only=False):
            request = self.factory.get("/")
            request.COOKIES["access"] = self.access_token
            self.assertIsNone(self.auth.authenticate(request))

    def test_cookie_takes_priority_over_header_when_both_enabled(self):
        other_user = User.objects.create_user(phone_number="+225000000061", password="qwerty123")
        other_token = str(RefreshToken.for_user(other_user).access_token)
        with jwt_modes(via_json=True, via_http_only=True):
            request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
            request.COOKIES["access"] = other_token
            user, token = self.auth.authenticate(request)
        self.assertEqual(user, other_user)

    def test_header_used_when_cookie_absent_and_both_enabled(self):
        with jwt_modes(via_json=True, via_http_only=True):
            request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {self.access_token}")
            user, token = self.auth.authenticate(request)
        self.assertEqual(user, self.user)

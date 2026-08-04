"""
Tests de src/forge_auth/throttling.py::ForgeAuthScopedRateThrottle.

Comportement attendu : no-op (jamais de 429, jamais de 500) tant que le
projet hôte n'a pas défini de débit pour le scope dans
REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] ; applique réellement la limite
sinon.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.throttling import ForgeAuthScopedRateThrottle

User = get_user_model()


class ThrottleIsNoOpByDefaultTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_many_login_attempts_are_never_throttled_without_configured_rate(self):
        for _ in range(20):
            response = self.client.post(
                reverse("forge_auth:users-login"), {"username": "+225000001500", "password": "wrong"}, format="json"
            )
            self.assertNotEqual(response.status_code, 429)


class ThrottleAppliesWhenConfiguredTestCase(TestCase):
    """
    `SimpleRateThrottle.THROTTLE_RATES = api_settings.DEFAULT_THROTTLE_RATES`
    est évalué une seule fois à l'import de `rest_framework.throttling` :
    `override_settings(REST_FRAMEWORK=...)` ne suffit donc pas à changer les
    débits dans un test (piège DRF connu) — on patch directement l'attribut
    de classe, seul moyen fiable de simuler un débit configuré ici.
    """

    def setUp(self):
        self.client = APIClient()
        cache.clear()
        self.addCleanup(cache.clear)
        self._original_rates = ForgeAuthScopedRateThrottle.THROTTLE_RATES
        ForgeAuthScopedRateThrottle.THROTTLE_RATES = {"forge_auth_login": "2/min"}
        self.addCleanup(setattr, ForgeAuthScopedRateThrottle, "THROTTLE_RATES", self._original_rates)

    def test_throttles_after_configured_limit(self):
        statuses = []
        for _ in range(3):
            response = self.client.post(
                reverse("forge_auth:users-login"), {"username": "+225000001501", "password": "wrong"}, format="json"
            )
            statuses.append(response.status_code)
        self.assertIn(429, statuses)

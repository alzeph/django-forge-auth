"""
Tests du verrouillage de compte après échecs répétés :
src/forge_auth/models.py::User.register_failed_login/register_successful_login/is_locked,
src/forge_auth/serializers.py::_check_not_locked, FORGE_AUTH["ACCOUNT_LOCKOUT"].
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from forge_auth.conf import forge_auth_config
from tests._helpers import temporarily_disable_otp

User = get_user_model()


@contextmanager
def lockout_conf(max_attempts=3, lockout_duration=900):
    conf = forge_auth_config.account_lockout_conf
    original = (conf.MAX_ATTEMPTS, conf.LOCKOUT_DURATION)
    conf.MAX_ATTEMPTS, conf.LOCKOUT_DURATION = max_attempts, lockout_duration
    try:
        yield
    finally:
        conf.MAX_ATTEMPTS, conf.LOCKOUT_DURATION = original


class AccountLockoutTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000001100", password="qwerty123")
        self.login_url = reverse("forge_auth:users-login")

    def _fail_login(self):
        with temporarily_disable_otp():
            return self.client.post(
                self.login_url, {"username": self.user.username, "password": "wrong"}, format="json"
            )

    def _succeed_login(self):
        with temporarily_disable_otp():
            return self.client.post(
                self.login_url, {"username": self.user.username, "password": "qwerty123"}, format="json"
            )

    def test_locks_account_after_max_attempts(self):
        with lockout_conf(max_attempts=3):
            for _ in range(3):
                response = self._fail_login()
                self.assertEqual(response.status_code, 401)

            self.user.refresh_from_db()
            self.assertTrue(self.user.is_locked)

            # Même avec le bon mot de passe, le compte reste verrouillé.
            response = self._succeed_login()
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("access", response.data)

    def test_successful_login_resets_counter(self):
        with lockout_conf(max_attempts=3):
            self._fail_login()
            self._fail_login()
            response = self._succeed_login()
            self.assertEqual(response.status_code, 200)

            self.user.refresh_from_db()
            self.assertEqual(self.user.failed_login_attempts, 0)
            self.assertIsNone(self.user.locked_until)

    def test_disabled_when_max_attempts_is_none(self):
        with lockout_conf(max_attempts=None):
            for _ in range(10):
                self._fail_login()
            self.user.refresh_from_db()
            self.assertFalse(self.user.is_locked)
            self.assertEqual(self.user.failed_login_attempts, 0)

    def test_lock_expires_after_duration(self):
        with lockout_conf(max_attempts=1, lockout_duration=900):
            self._fail_login()
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_locked)

        # Simule l'expiration du verrou.
        self.user.locked_until = timezone.now() - timezone.timedelta(seconds=1)
        self.user.save(update_fields=["locked_until"])
        self.assertFalse(self.user.is_locked)

        response = self._succeed_login()
        self.assertEqual(response.status_code, 200)

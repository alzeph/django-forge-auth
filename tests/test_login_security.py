"""
Tests de `_ensure_account_usable` (src/forge_auth/serializers.py), câblée
dans LoginSerializer, LoginSerializerF2FA_STEP1 et LoginSerializerF2FA_STEP2.

Régression : le flux JWT de forge_auth n'appelle jamais
`django.contrib.auth.authenticate()` (qui vérifierait normalement
`is_active` via `ModelBackend.user_can_authenticate`) ; il vérifie le mot de
passe/OTP directement sur l'instance `User`. Avant ce correctif, ni
`is_active=False`, ni `status` in {BLOCKED, SUSPENDED, DEACTIVATED} (le
seul statut bloquant était DELETED, via `User.get()`) n'empêchaient la
délivrance d'un JWT valide : `mark_as_suspended()`/`deactivate_user()`
étaient donc des méthodes sans aucun effet réel sur l'authentification.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.models import OtpToken, StatusMixin
from tests._helpers import temporarily_disable_otp

User = get_user_model()

StatusVerified = StatusMixin.StatusVerified


class LoginBlocksUnusableAccountsTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000400", password="qwerty123")
        self.login_url = reverse("forge_auth:users-login")

    def _login_with_password(self):
        return self.client.post(
            self.login_url, {"username": self.user.username, "password": "qwerty123"}, format="json"
        )

    def _login_with_otp(self):
        otp_token, _ = OtpToken.objects.get_or_create(user=self.user)
        code = otp_token.generate_otp()
        return self.client.post(self.login_url, {"username": self.user.username, "code": code}, format="json")

    def test_active_verified_user_can_login_with_password(self):
        with temporarily_disable_otp():
            response = self._login_with_password()
        self.assertEqual(response.status_code, 200)

    def test_active_verified_user_can_login_with_otp(self):
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 200)

    def test_inactive_user_cannot_login_with_password(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        with temporarily_disable_otp():
            response = self._login_with_password()
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.data)

    def test_inactive_user_cannot_login_with_otp(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 401)

    def test_suspended_user_cannot_login(self):
        self.user.mark_as_suspended()
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 401)

    def test_blocked_user_cannot_login(self):
        self.user.status = StatusVerified.BLOCKED
        self.user.save(update_fields=["status"])
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 401)

    def test_deactivated_user_cannot_login(self):
        self.user.deactivate_user()
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 401)

    def test_unverified_user_can_still_login(self):
        # UNVERIFIED n'est pas dans is_unauthorized : seule une vérification
        # explicite (mark_as_verified) ou un blocage doit changer ce statut.
        self.assertEqual(self.user.status, StatusVerified.UNVERIFIED)
        response = self._login_with_otp()
        self.assertEqual(response.status_code, 200)


class F2FALoginBlocksUnusableAccountsTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000401", password="qwerty123")

    def test_authenticate_user_step1_rejects_inactive_account(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        response = self.client.post(
            reverse("forge_auth:users-authenticate-user"),
            {"username": self.user.username, "password": "qwerty123"},
            format="json",
        )
        self.assertEqual(response.status_code, 401)

    def test_verify_otp_and_login_step2_rejects_suspended_account(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp()
        self.user.mark_as_suspended()
        response = self.client.post(
            reverse("forge_auth:users-verify-otp-and-login"),
            {"username": self.user.username, "code": code},
            format="json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.data)

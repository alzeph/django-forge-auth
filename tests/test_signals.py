"""
Tests des signaux forge_auth (src/forge_auth/signals.py) :

- user_logged_in / otp_requested : signaux applicatifs envoyés par
  UserViewSet (login / obtain_otp), le point d'extension prévu pour que le
  projet hôte branche des actions personnalisées.
- create_superuser / initialize_groups : receivers post_migrate existants.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from forge_auth.conf import forge_auth_config
from forge_auth.models import OtpToken
from forge_auth.signals import (
    create_superuser,
    initialize_groups,
    otp_requested,
    user_logged_in,
)
from tests._helpers import forge_auth_override, temporarily_disable_otp

User = get_user_model()


class SignalRecorder:
    """Petit espion réutilisable pour les tests de signaux."""

    def __init__(self):
        self.calls = []

    def __call__(self, sender, **kwargs):
        self.calls.append(kwargs)

    @property
    def call_count(self):
        return len(self.calls)


class UserLoggedInSignalTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000070", password="qwerty123")
        self.recorder = SignalRecorder()
        user_logged_in.connect(self.recorder)
        self.addCleanup(user_logged_in.disconnect, self.recorder)

    def test_sent_on_successful_password_login(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": "+225000000070", "password": "qwerty123"},
                format="json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.recorder.call_count, 1)
        self.assertEqual(self.recorder.calls[0]["user"], self.user)
        self.assertIn("request", self.recorder.calls[0])

    def test_sent_on_successful_otp_login(self):
        otp_token, _ = OtpToken.objects.get_or_create(user=self.user)
        code = otp_token.generate_otp()
        response = self.client.post(
            reverse("forge_auth:users-login"),
            {"username": "+225000000070", "code": code},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.recorder.call_count, 1)
        self.assertEqual(self.recorder.calls[0]["user"], self.user)

    def test_not_sent_on_failed_login(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-login"),
                {"username": "+225000000070", "password": "wrong-password"},
                format="json",
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.recorder.call_count, 0)

    def test_not_sent_on_missing_data(self):
        response = self.client.post(reverse("forge_auth:users-login"), {}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.recorder.call_count, 0)


class OtpRequestedSignalTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(phone_number="+225000000071", password="qwerty123")
        self.recorder = SignalRecorder()
        otp_requested.connect(self.recorder)
        self.addCleanup(otp_requested.disconnect, self.recorder)

    def test_sent_on_successful_otp_request(self):
        response = self.client.post(
            reverse("forge_auth:users-obtain-otp"),
            {"username": "+225000000071"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.recorder.call_count, 1)
        call = self.recorder.calls[0]
        self.assertEqual(call["user"], self.user)
        self.assertIn("request", call)
        self.assertTrue(call["otp_token"].otp_code)

    def test_not_sent_for_unknown_user(self):
        # UsernameSerializer rejette déjà les usernames inconnus en amont
        # (sauf REGISTER_INCLUDE_IN_OTP) : la vue répond 400, pas 404.
        response = self.client.post(
            reverse("forge_auth:users-obtain-otp"),
            {"username": "+225000000000"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.recorder.call_count, 0)

    def test_not_sent_when_otp_disabled(self):
        with temporarily_disable_otp():
            response = self.client.post(
                reverse("forge_auth:users-obtain-otp"),
                {"username": "+225000000071"},
                format="json",
            )
        self.assertEqual(response.status_code, 405)
        self.assertEqual(self.recorder.call_count, 0)


class PostMigrateSuperuserSignalTestCase(TestCase):
    def setUp(self):
        # Le receiver post_migrate réel tourne déjà une fois à la création
        # de la base de test (migrate initial), avant toute transaction de
        # test : un superutilisateur "admin" existe donc déjà par défaut.
        # On repart d'un état propre pour tester create_superuser en
        # isolation.
        User.objects.filter(is_superuser=True).delete()

    def test_creates_default_superuser_when_none_exists(self):
        self.assertFalse(User.objects.filter(is_superuser=True).exists())
        create_superuser(sender=None)
        self.assertTrue(User.objects.filter(is_superuser=True, phone_number="admin").exists())

    def test_does_not_create_a_second_superuser(self):
        User.objects.create_superuser(phone_number="+225000000080", password="qwerty123")
        create_superuser(sender=None)
        self.assertEqual(User.objects.filter(is_superuser=True).count(), 1)
        self.assertFalse(User.objects.filter(phone_number="admin").exists())

    def test_uses_configured_credentials(self):
        with forge_auth_override(CREDENTIALS_SUPERUSER={"username": "+225099999999", "password": "s3cret!"}):
            create_superuser(sender=None)
        user = User.objects.get(phone_number="+225099999999")
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.check_password("s3cret!"))


class PostMigrateGroupsSignalTestCase(TestCase):
    def test_creates_configured_groups(self):
        with forge_auth_override(GROUPS=["clients", "staff"]):
            initialize_groups(sender=None)
        self.assertEqual(
            set(Group.objects.filter(name__in=["clients", "staff"]).values_list("name", flat=True)),
            {"clients", "staff"},
        )

    def test_is_idempotent(self):
        with forge_auth_override(GROUPS=["clients"]):
            initialize_groups(sender=None)
            initialize_groups(sender=None)
        self.assertEqual(Group.objects.filter(name="clients").count(), 1)

    def test_no_groups_configured_creates_nothing(self):
        Group.objects.all().delete()
        initialize_groups(sender=None)
        self.assertEqual(Group.objects.count(), 0)

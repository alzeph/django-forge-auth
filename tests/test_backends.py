"""
Tests de MultiFieldBackend (src/forge_auth/backends.py).

USERNAME_FIELD étant figé au chargement de l'app (voir CLAUDE.md), ces
tests utilisent la config par défaut des tests (phone_number) et branchent
ALTERNATIVE_USERNAME_FIELDS via forge_auth_override, qui est lu à chaque
appel par le backend (pas mis en cache en attribut d'instance).
"""
from django.contrib.auth import get_user_model
from django.test import TestCase

from forge_auth.backends import MultiFieldBackend
from tests._helpers import forge_auth_override

User = get_user_model()


class MultiFieldBackendTestCase(TestCase):
    def setUp(self):
        self.backend = MultiFieldBackend()
        self.user = User.objects.create_user(
            phone_number="+225000000050",
            email="backend@example.com",
            password="qwerty123",
        )

    def test_authenticate_with_no_username_returns_none(self):
        self.assertIsNone(self.backend.authenticate(None, username=None, password="qwerty123"))

    def test_authenticate_success_on_main_field(self):
        user = self.backend.authenticate(None, username="+225000000050", password="qwerty123")
        self.assertEqual(user, self.user)

    def test_authenticate_wrong_password_returns_none(self):
        user = self.backend.authenticate(None, username="+225000000050", password="wrong")
        self.assertIsNone(user)

    def test_authenticate_unknown_username_returns_none(self):
        user = self.backend.authenticate(None, username="+225000000000", password="qwerty123")
        self.assertIsNone(user)

    def test_authenticate_is_case_insensitive(self):
        with forge_auth_override(ALTERNATIVE_USERNAME_FIELDS=["email"]):
            user = self.backend.authenticate(None, username="BACKEND@EXAMPLE.COM", password="qwerty123")
        self.assertEqual(user, self.user)

    def test_authenticate_alternative_field_not_active_by_default(self):
        # ALTERNATIVE_USERNAME_FIELDS=[] par défaut : l'email n'est pas
        # cherché tant qu'il n'est pas explicitement déclaré.
        user = self.backend.authenticate(None, username="backend@example.com", password="qwerty123")
        self.assertIsNone(user)

    def test_authenticate_via_alternative_field(self):
        with forge_auth_override(ALTERNATIVE_USERNAME_FIELDS=["email"]):
            user = self.backend.authenticate(None, username="backend@example.com", password="qwerty123")
        self.assertEqual(user, self.user)

    def test_authenticate_inactive_user_returns_none(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        user = self.backend.authenticate(None, username="+225000000050", password="qwerty123")
        self.assertIsNone(user)

    def test_authenticate_multiple_objects_returned_returns_none(self):
        with forge_auth_override(ALTERNATIVE_USERNAME_FIELDS=["email"]):
            # un second utilisateur dont le phone_number correspond à
            # l'email du premier : la requête Q OR remonte les deux lignes.
            User.objects.create_user(
                phone_number="backend@example.com",
                email="other@example.com",
                password="qwerty123",
            )
            user = self.backend.authenticate(None, username="backend@example.com", password="qwerty123")
        self.assertIsNone(user)

"""
Tests du modèle User dynamique et de OtpToken (src/forge_auth/models.py).

La config FORGE_AUTH par défaut des tests (tests/settings.py, FORGE_AUTH={})
active StatusMixin et OtpSecretMixin (OPTIONAL_FIELDS=[]) : ces tests
couvrent donc le modèle tel que construit avec la configuration par défaut.
Voir CLAUDE.md sur le fait que OPTIONAL_FIELDS n'est lu qu'au chargement du
module et ne peut pas être changé dynamiquement en cours de test.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from forge_auth.models import OtpToken, StatusMixin
from tests._helpers import forge_auth_override

User = get_user_model()


class UserManagerTestCase(TestCase):
    def test_create_user_requires_username_field(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(password="qwerty123")

    def test_create_user_hashes_password(self):
        user = User.objects.create_user(phone_number="+225000000001", password="qwerty123")
        self.assertNotEqual(user.password, "qwerty123")
        self.assertTrue(user.check_password("qwerty123"))

    def test_create_user_assigns_groups_and_permissions(self):
        from django.contrib.auth.models import Group, Permission

        group = Group.objects.create(name="testers")
        permission = Permission.objects.first()
        user = User.objects.create_user(
            phone_number="+225000000002",
            password="qwerty123",
            groups=[group],
            user_permissions=[permission],
        )
        self.assertIn(group, user.groups.all())
        self.assertIn(permission, user.user_permissions.all())

    def test_create_superuser_sets_staff_and_superuser_flags(self):
        user = User.objects.create_superuser(phone_number="+225000000003", password="qwerty123")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)


class UserPropertiesTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            phone_number="+225000000010",
            email="jane@example.com",
            first_name="Jane",
            last_name="Doe",
            password="qwerty123",
        )

    def test_username_property_returns_username_field_value(self):
        self.assertEqual(self.user.username, self.user.phone_number)

    def test_full_name(self):
        self.assertEqual(self.user.full_name, "Jane Doe")

    def test_is_valid_email_true(self):
        self.assertTrue(self.user.is_valid_email)

    def test_is_valid_email_false(self):
        self.user.email = "not-an-email"
        self.assertFalse(self.user.is_valid_email)

    def test_is_valid_phone_number_true(self):
        self.assertTrue(self.user.is_valid_phone_number)

    def test_is_valid_phone_number_false(self):
        self.user.phone_number = "abc"
        self.assertFalse(self.user.is_valid_phone_number)


class UserGetTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000020", password="qwerty123")

    def test_get_success_by_username_field(self):
        found = User.get("+225000000020")
        self.assertEqual(found.pk, self.user.pk)

    def test_get_is_case_insensitive_and_checks_alternative_fields(self):
        User.objects.create_user(phone_number="+225000000021", email="Case@Example.com", password="qwerty123")
        with forge_auth_override(ALTERNATIVE_USERNAME_FIELDS=["email"]):
            found = User.get("case@example.com")
        self.assertEqual(found.email, "Case@Example.com")

    def test_get_raises_does_not_exist(self):
        with self.assertRaises(User.DoesNotExist):
            User.get("+225000000099")

    def test_get_raises_permission_error_for_deleted_account(self):
        self.user.status = StatusMixin.StatusVerified.DELETED
        self.user.save(update_fields=["status"])
        with self.assertRaises(PermissionError):
            User.get("+225000000020")


class StatusMixinTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000030", password="qwerty123")

    def test_default_status_is_unverified(self):
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.UNVERIFIED)
        self.assertFalse(self.user.is_verified)
        self.assertFalse(self.user.is_unauthorized)

    def test_mark_as_verified(self):
        self.user.mark_as_verified()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.VERIFIED)
        self.assertTrue(self.user.is_verified)

    def test_mark_as_unverified(self):
        self.user.mark_as_verified()
        self.user.mark_as_unverified()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.UNVERIFIED)

    def test_mark_as_suspended_is_unauthorized(self):
        self.user.mark_as_suspended()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.SUSPENDED)
        self.assertTrue(self.user.is_unauthorized)

    def test_deactivate_user_is_unauthorized(self):
        self.user.deactivate_user()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.DEACTIVATED)
        self.assertTrue(self.user.is_unauthorized)

    def test_delete_user_is_unauthorized(self):
        self.user.delete_user()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.DELETED)
        self.assertTrue(self.user.is_unauthorized)

    def test_status_changes_persist_to_db(self):
        self.user.mark_as_verified()
        self.user.refresh_from_db()
        self.assertEqual(self.user.status, StatusMixin.StatusVerified.VERIFIED)


class OtpTokenTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000040", password="qwerty123")

    def test_generate_otp_returns_code_with_configured_digits(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp()
        self.assertEqual(len(code), 4)
        self.assertTrue(code.isdigit())

    def test_generate_otp_can_override_digits(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp(digits=6)
        self.assertEqual(len(code), 6)

    def test_generate_otp_stores_plaintext_and_hashed_token(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp()
        otp_token.refresh_from_db()
        self.assertEqual(otp_token.otp_code, code)
        self.assertNotEqual(otp_token.token, code)

    @override_settings(DEBUG=True)
    def test_verify_otp_always_true_when_debug(self):
        otp_token = OtpToken.objects.create(user=self.user)
        otp_token.generate_otp()
        self.assertTrue(otp_token.verify_otp("wrong-code"))

    @override_settings(DEBUG=False)
    def test_verify_otp_checks_code_when_not_debug(self):
        otp_token = OtpToken.objects.create(user=self.user)
        code = otp_token.generate_otp()
        self.assertTrue(otp_token.verify_otp(code))
        self.assertFalse(otp_token.verify_otp("wrong-code"))

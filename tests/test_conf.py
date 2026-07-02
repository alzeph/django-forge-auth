"""
Tests de ForgeAuthConfig (src/forge_auth/conf.py).

Chaque test instancie sa propre ForgeAuthConfig() plutôt que d'utiliser le
singleton partagé forge_auth_config, pour ne pas polluer l'état global lu
par le reste de l'app (voir tests/_helpers.py pour les cas où le singleton
partagé doit être manipulé).
"""
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from forge_auth.conf import ForgeAuthConfig


class ValidateTestCase(TestCase):
    def _validate(self):
        config = ForgeAuthConfig()
        config.validate()
        return config

    @override_settings(FORGE_AUTH={})
    def test_validates_successfully_with_defaults(self):
        config = self._validate()
        self.assertEqual(config.get("USERNAME_FIELD"), "phone_number")
        self.assertEqual(config.get("OPTIONAL_FIELDS"), [])
        self.assertEqual(config.get("ALTERNATIVE_USERNAME_FIELDS"), [])
        self.assertEqual(config.get("GROUPS"), [])
        self.assertIsNone(config.get("GROUP_DEFAULT"))

    @override_settings(FORGE_AUTH={"NOT_A_REAL_KEY": True})
    def test_rejects_unknown_key(self):
        with self.assertRaises(ImproperlyConfigured):
            self._validate()

    @override_settings(FORGE_AUTH={"OPTIONAL_FIELDS": "status"})
    def test_rejects_optional_fields_not_a_collection(self):
        with self.assertRaises(ImproperlyConfigured):
            self._validate()

    @override_settings(FORGE_AUTH={"OPTIONAL_FIELDS": ["not_a_valid_field"]})
    def test_rejects_unknown_optional_field_value(self):
        with self.assertRaises(ImproperlyConfigured):
            self._validate()

    @override_settings(FORGE_AUTH={"OPTIONAL_FIELDS": ["status", "otp_secret"]})
    def test_accepts_all_known_optional_fields(self):
        config = self._validate()
        self.assertEqual(set(config.get("OPTIONAL_FIELDS")), {"status", "otp_secret"})

    @override_settings(FORGE_AUTH={"USERNAME_FIELD": "username"})
    def test_rejects_invalid_username_field(self):
        with self.assertRaises(ImproperlyConfigured):
            self._validate()

    @override_settings(FORGE_AUTH={"USERNAME_FIELD": "email"})
    def test_accepts_email_as_username_field(self):
        config = self._validate()
        self.assertEqual(config.get("USERNAME_FIELD"), "email")

    @override_settings(FORGE_AUTH={
        "USERNAME_FIELD": "email",
        "ALTERNATIVE_USERNAME_FIELDS": ["phone_number"],
        "OPTIONAL_FIELDS": ["status"],
        "OTP": {"USE_OTP": False},
        "JWT": {"VIA_JSON": False, "VIA_HTTP_ONLY": True},
        "REGISTER_INCLUDE_IN_OTP": True,
        "GROUPS": ["clients", "staff"],
        "GROUP_DEFAULT": "clients",
    })
    def test_accepts_a_fully_customized_config(self):
        config = self._validate()
        self.assertEqual(config.get("USERNAME_FIELD"), "email")
        self.assertEqual(config.get("ALTERNATIVE_USERNAME_FIELDS"), ["phone_number"])
        self.assertEqual(config.get("OPTIONAL_FIELDS"), ["status"])
        self.assertEqual(config.get("GROUPS"), ["clients", "staff"])
        self.assertEqual(config.get("GROUP_DEFAULT"), "clients")

    def test_multiple_errors_are_all_reported(self):
        with override_settings(FORGE_AUTH={
            "NOT_A_REAL_KEY": True,
            "USERNAME_FIELD": "username",
            "OPTIONAL_FIELDS": ["not_a_valid_field"],
        }):
            config = ForgeAuthConfig()
            with self.assertRaises(ImproperlyConfigured) as ctx:
                config.validate()
            message = str(ctx.exception)
            self.assertIn("Clés inconnues", message)
            self.assertIn("USERNAME_FIELD", message)
            self.assertIn("OPTIONAL_FIELDS", message)


class ConstructionCrashesOnNonDictNestedConfigTestCase(TestCase):
    """
    Bug connu : CREDENTIALS_SUPERUSER / OTP / JWT sont transformés en objets
    (CredentialSuperuserConf / OTPConf / JWTConf) dès la construction de
    ForgeAuthConfig (voir __init__ -> get() -> _merge_conf()), AVANT que
    validate() n'ait la main. Un type invalide sur ces clés fait donc
    planter avec un TypeError brut à la construction (et donc au démarrage
    de Django, puisque `forge_auth_config = ForgeAuthConfig()` s'exécute à
    l'import de conf.py) plutôt que de déclencher le message
    ImproperlyConfigured propre que validate() est censé produire.

    Ces tests documentent le comportement actuel (pas le comportement
    désiré) pour qu'il ne surprenne pas un futur contributeur.
    """

    @override_settings(FORGE_AUTH={"OTP": ["not", "a", "dict"]})
    def test_non_dict_otp_raises_typeerror_at_construction(self):
        with self.assertRaises(TypeError):
            ForgeAuthConfig()

    @override_settings(FORGE_AUTH={"JWT": ["not", "a", "dict"]})
    def test_non_dict_jwt_raises_typeerror_at_construction(self):
        with self.assertRaises(TypeError):
            ForgeAuthConfig()

    @override_settings(FORGE_AUTH={"CREDENTIALS_SUPERUSER": ["not", "a", "dict"]})
    def test_non_dict_credentials_superuser_raises_typeerror_at_construction(self):
        with self.assertRaises(TypeError):
            ForgeAuthConfig()


class HelperMethodsTestCase(TestCase):
    @override_settings(FORGE_AUTH={
        "USERNAME_FIELD": "email",
        "ALTERNATIVE_USERNAME_FIELDS": ["phone_number"],
        "OPTIONAL_FIELDS": ["status"],
    })
    def test_is_username_field(self):
        config = ForgeAuthConfig()
        self.assertTrue(config.is_username_field("email"))
        self.assertTrue(config.is_username_field("phone_number"))
        self.assertFalse(config.is_username_field("otp_secret"))

    @override_settings(FORGE_AUTH={"OPTIONAL_FIELDS": ["status"]})
    def test_is_enabled_field(self):
        config = ForgeAuthConfig()
        self.assertFalse(config.is_enabled_field("status"))
        self.assertTrue(config.is_enabled_field("otp_secret"))

    @override_settings(FORGE_AUTH={})
    def test_reset_clears_internal_cache(self):
        config = ForgeAuthConfig()
        config.get("USERNAME_FIELD")
        self.assertIsNotNone(config._resolved)
        config.reset()
        self.assertIsNone(config._resolved)

    @override_settings(FORGE_AUTH={"USERNAME_FIELD": "email"})
    def test_get_falls_back_to_defaults_for_unset_keys(self):
        config = ForgeAuthConfig()
        self.assertEqual(config.get("GROUPS"), [])

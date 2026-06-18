SECRET_KEY = "test-secret-key"
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "forge_auth",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

AUTH_USER_MODEL = "forge_auth.User"
ROOT_URLCONF = "tests.urls"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "forge_auth.authentification.JWTAuthenticationFlexible",
    ],
}

AUTHENTICATION_BACKENDS = [
    "forge_auth.backends.MultiFieldBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# Configuration FORGE_AUTH par défaut pour les tests.
# A adapter selon le scénario testé (OPTIONAL_FIELDS, USERNAME_FIELD, etc.).
FORGE_AUTH = {}

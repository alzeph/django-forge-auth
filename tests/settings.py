import tempfile

SECRET_KEY = "test-secret-key"
DEBUG = True

# Nécessaire pour ProfilePhotoMixin (ImageField) : hors du dépôt, dans un
# répertoire temporaire, pour ne jamais laisser de fichier uploadé traîner
# dans l'arbre du projet après les tests.
MEDIA_ROOT = tempfile.mkdtemp(prefix="forge_auth_test_media_")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "forge_auth",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
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
        # Optionnel côté lib (voir authentification.py::ApiKeyAuthentication) :
        # activé ici pour pouvoir tester le flux clés API de bout en bout.
        "forge_auth.authentification.ApiKeyAuthentication",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
}

AUTHENTICATION_BACKENDS = [
    "forge_auth.backends.MultiFieldBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# AUTH_PASSWORD_VALIDATORS est [] par défaut dans Django (contrairement au
# settings.py généré par `startproject`) : on reprend ici la configuration
# standard pour exercer la validation de mot de passe de forge_auth
# (UserSerializer.update, change-password, confirm-password-reset).
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Configuration FORGE_AUTH par défaut pour les tests.
# A adapter selon le scénario testé (OPTIONAL_FIELDS, USERNAME_FIELD, etc.).
FORGE_AUTH = {}

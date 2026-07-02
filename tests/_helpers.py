"""
Utilitaires partagés entre les modules de tests.

Non collecté par pytest (voir `python_files` dans pyproject.toml : seuls
`tests.py` et `test_*.py` le sont).
"""
from contextlib import contextmanager

from django.test import override_settings

from forge_auth.conf import forge_auth_config


@contextmanager
def temporarily_disable_otp():
    """
    ``forge_auth_config.otp_conf`` est un objet construit une seule fois à
    l'initialisation du singleton (voir ``ForgeAuthConfig.__init__``) :
    changer ``settings.FORGE_AUTH`` via ``override_settings()`` ne le fait
    PAS réévaluer, même après ``forge_auth_config.reset()`` (qui ne vide que
    le cache interne ``_resolved``, pas les attributs ``otp_conf`` /
    ``jwt_conf`` / ``optional_fields`` déjà matérialisés en instance). On
    mute donc directement l'objet vivant, partagé par toute l'app.
    """
    original = forge_auth_config.otp_conf.USE_OTP
    forge_auth_config.otp_conf.USE_OTP = False
    try:
        yield
    finally:
        forge_auth_config.otp_conf.USE_OTP = original


@contextmanager
def forge_auth_override(**forge_auth_settings):
    """
    Pour les clés lues via ``forge_auth_config.get(...)`` à chaque appel
    (``GROUPS``, ``CREDENTIALS_SUPERUSER``, ``USERNAME_FIELD`` via
    ``get_username_field()``) : ``override_settings`` + ``reset()``
    fonctionne correctement, contrairement à ``otp_conf``/``jwt_conf``
    (voir ``temporarily_disable_otp``).
    """
    with override_settings(FORGE_AUTH=forge_auth_settings):
        forge_auth_config.reset()
        try:
            yield
        finally:
            forge_auth_config.reset()

from django.core.exceptions import ImproperlyConfigured
from rest_framework.throttling import ScopedRateThrottle


class ForgeAuthScopedRateThrottle(ScopedRateThrottle):
    """
    ``ScopedRateThrottle`` standard, mais qui ne casse pas le démarrage/les
    requêtes si le projet hôte n'a pas défini de débit pour le scope
    concerné dans ``REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]`` : dans ce cas
    (`ImproperlyConfigured`), on désactive silencieusement la limite plutôt
    que de lever une 500. Le débit reste entièrement configurable côté hôte
    en ajoutant simplement la clé de scope correspondante (voir README,
    section "Throttling").
    """

    def get_rate(self):
        try:
            return super().get_rate()
        except ImproperlyConfigured:
            return None

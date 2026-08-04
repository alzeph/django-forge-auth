"""
Vérification d'id_token OIDC pour la connexion sociale générique
(FORGE_AUTH["SOCIAL_AUTH"]).

Implémentation volontairement minimale et sans dépendance à un SDK
spécifique à un fournisseur : n'importe quel fournisseur conforme OpenID
Connect (Google, Microsoft, Apple...) fonctionne dès qu'on lui fournit
`ISSUER` et `CLIENT_ID` dans la configuration.

`verify_id_token` est le point d'entrée à mocker dans les tests (voir
`tests/test_social_auth.py`) : vérifier un vrai id_token nécessite un appel
réseau vers le fournisseur (découverte de `jwks_uri`, récupération des clés
publiques), ce qui n'a pas sa place dans une suite de tests unitaires.
"""
import json
import urllib.request

import jwt
from jwt import PyJWKClient


def _discover_jwks_uri(issuer: str) -> str:
    """Récupère `jwks_uri` via le document de découverte OIDC standard."""
    well_known_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with urllib.request.urlopen(well_known_url, timeout=5) as response:
        config = json.load(response)
    return config["jwks_uri"]


def verify_id_token(id_token: str, *, issuer: str, audience: str) -> dict:
    """
    Vérifie la signature (via les clés publiques JWKS du fournisseur),
    l'émetteur et l'audience d'un id_token OIDC.

    Retourne les claims décodés (dont `sub`, `email`...) si valide.
    Lève `jwt.PyJWTError` (ou une sous-classe) si invalide/expiré/falsifié.
    """
    jwks_uri = _discover_jwks_uri(issuer)
    signing_key = PyJWKClient(jwks_uri).get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )

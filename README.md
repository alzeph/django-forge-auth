# forge-auth

Application Django réutilisable fournissant un système d'authentification complet : utilisateur personnalisé, connexion par mot de passe ou par code OTP (one-time password), JWT (header ou cookie httponly), gestion de groupes/permissions et endpoints REST prêts à l'emploi (Django REST Framework).

## Sommaire

- Fonctionnalités
- Installation
- Configuration rapide
- Référence complète des options `FORGE_AUTH`
- Scénarios de configuration détaillés
- Endpoints de l'API
- Permissions : `IsSelfOrAdmin`
- Throttling
- Exemples d'utilisation
- Modèle `User` : méthodes et propriétés utiles
- Signal `user_logged_in`
- Signal `otp_requested`
- Signal `password_reset_requested`
- Avertissement sur les migrations
- Points non automatisés (à implémenter côté projet hôte)
- Notes de sécurité
- Lancer les tests

## Fonctionnalités

- Modèle `User` personnalisé sans champ `username` imposé : authentification par `phone_number`, `email`, ou les deux.
- Champs `status` (vérification de compte) et `otp_secret` (TOTP) optionnels et désactivables.
- Authentification par mot de passe ou par code OTP, au choix.
- JWT via header `Authorization: Bearer` ou via cookies httponly, au choix (les deux peuvent être actifs simultanément).
- Backend d'authentification Django supportant plusieurs champs de connexion (`MultiFieldBackend`).
- ViewSets DRF prêts à l'emploi : inscription, connexion, déconnexion, rafraîchissement de token, vérification d'unicité email/téléphone, utilisateur courant, vérification de session, changement de mot de passe, mot de passe oublié.
- Contrôle d'accès par objet (`IsSelfOrAdmin`) sur `/users/` : un utilisateur ne voit/modifie que lui-même, le staff voit tout.
- Limitation de débit (throttling) configurable sur les endpoints sensibles (login, OTP, refresh, reset de mot de passe).
- Documentation OpenAPI via `drf-spectacular` (`extend_schema` déjà posé sur chaque action).
- Validation de configuration au démarrage (`AppConfig.ready()`), qui stoppe le serveur si `FORGE_AUTH` est mal formé.

## Installation

Le package est structuré en layout `src/` et se construit avec `hatchling`. Avec `uv`, depuis le projet Django qui consomme `forge-auth` :

```bash
# Installation depuis un chemin local
uv add /chemin/vers/forge_auth

# Ou depuis un dépôt git
uv add git+https://exemple.com/forge_auth.git

# Ou en mode editable pendant le développement du package lui-même
uv pip install -e /chemin/vers/forge_auth
```

Dépendances installées automatiquement : `django`, `djangorestframework`, `djangorestframework-simplejwt`, `pyotp`, `drf-spectacular`.

## Configuration rapide

Dans `settings.py` du projet hôte :

```python
INSTALLED_APPS = [
    # ...
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "forge_auth",
]

AUTH_USER_MODEL = "forge_auth.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "forge_auth.authentification.JWTAuthenticationFlexible",
    ],
}

# Nécessaire uniquement si vous voulez l'authentification Django classique
# (admin, formulaires) avec plusieurs champs de login.
AUTHENTICATION_BACKENDS = [
    "forge_auth.backends.MultiFieldBackend",
    "django.contrib.auth.backends.ModelBackend",
]

# [] par défaut dans Django (pas de validation) : à renseigner explicitement
# si vous voulez que la création de compte, le changement de mot de passe et
# la réinitialisation de mot de passe rejettent les mots de passe faibles.
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Optionnel : débits de limitation de requêtes sur les endpoints sensibles
# de forge_auth (no-op si absent, voir section "Throttling").
REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {
    "forge_auth_login": "10/min",
    "forge_auth_otp": "5/min",
    "forge_auth_refresh": "30/min",
    "forge_auth_password_reset": "5/min",
}

FORGE_AUTH = {}  # voir section "Référence complète" et "Scénarios"
```

Dans `urls.py` du projet hôte :

```python
from django.urls import include, path

urlpatterns = [
    path("api/", include("forge_auth.urls")),
]
```

Les routes de `forge_auth.urls` incluent déjà le préfixe `forge_auth/` : avec l'exemple ci-dessus, l'endpoint de connexion devient `/api/forge_auth/users/login/`.

Puis :

```bash
python manage.py migrate
```

## Référence complète des options `FORGE_AUTH`

Toutes les clés sont optionnelles ; les valeurs ci-dessous sont les valeurs par défaut.

| Clé | Type | Défaut | Rôle |
|---|---|---|---|
| `USERNAME_FIELD` | `"phone_number"` \| `"email"` | `"phone_number"` | Champ utilisé comme identifiant principal de connexion. |
| `ALTERNATIVE_USERNAME_FIELDS` | `list[str]` | `[]` | Champs additionnels acceptés comme identifiant (ex. `["email"]`). |
| `OPTIONAL_FIELDS` | `list["status" \| "otp_secret"]` | `[]` | Champs à retirer du modèle `User`. Présents dans cette liste = désactivés. |
| `OTP` | `dict` | voir ci-dessous | Configuration du système OTP. |
| `OTP.USE_OTP` | `bool` | `True` | Active la connexion par code OTP plutôt que par mot de passe. |
| `OTP.OTP_LIFETIME` | `int` (secondes) | `300` | Durée de vie indicative du code (non appliquée automatiquement, voir plus bas). |
| `OTP.OTP_DIGITS` | `int` | `4` | Nombre de chiffres du code généré. |
| `OTP.OTP_CANAL` | `"SMS"` \| `"APP"` \| `"MAIL"` \| `"WHATSAPP"` | `"WHATSAPP"` | Canal prévu pour la distribution du code (métadonnée, voir "Points non automatisés"). |
| `JWT` | `dict` | voir ci-dessous | Configuration de la distribution des tokens. |
| `JWT.VIA_JSON` | `bool` | `True` | Renvoie `access`/`refresh` dans le corps JSON de la réponse de login. |
| `JWT.VIA_HTTP_ONLY` | `bool` | `False` | Pose `access`/`refresh` en cookies httponly. |
| `REGISTER_INCLUDE_IN_OTP` | `bool` | `False` | Si `True`, `obtain-otp` crée l'utilisateur s'il n'existe pas encore (auto-inscription via OTP). |
| `CREDENTIALS_SUPERUSER` | `dict {username, password}` | `{"username": "admin", "password": "admin"}` | Réservé, voir "Points non automatisés". |
| `GROUP_DEFAULT` | `str \| None` | `None` | Réservé, voir "Points non automatisés". |
| `GROUPS` | `list[str]` | `[]` | Réservé, voir "Points non automatisés". |

Toute clé inconnue ou mal typée fait échouer le démarrage de Django avec un message listant précisément les erreurs (`ImproperlyConfigured`).

## Scénarios de configuration détaillés

### Scénario 1 — Défaut : téléphone + OTP WhatsApp

Aucune configuration nécessaire :

```python
FORGE_AUTH = {}
```

Flux de connexion :

1. `POST /forge_auth/users/` pour créer le compte (`phone_number` requis).
2. `POST /forge_auth/users/obtain-otp/` avec `{"username": "<phone_number>"}` génère et stocke un code.
3. `POST /forge_auth/users/login/` avec `{"username": "<phone_number>", "code": "<code>"}`.

### Scénario 2 — Email + mot de passe classique, sans OTP ni statut

```python
FORGE_AUTH = {
    "USERNAME_FIELD": "email",
    "OPTIONAL_FIELDS": ["status", "otp_secret"],
    "OTP": {"USE_OTP": False},
}
```

`OPTIONAL_FIELDS` retire `StatusMixin` et `OtpSecretMixin` du modèle `User` ; `OtpToken` redevient une classe factice. Flux de connexion :

```
POST /forge_auth/users/login/
{"username": "alice@exemple.com", "password": "motdepasse"}
```

Voir "Avertissement sur les migrations" avant d'utiliser ce scénario en production.

### Scénario 3 — Identifiant multiple (email ou téléphone) + mot de passe

```python
FORGE_AUTH = {
    "USERNAME_FIELD": "email",
    "ALTERNATIVE_USERNAME_FIELDS": ["phone_number"],
    "OPTIONAL_FIELDS": ["otp_secret"],
    "OTP": {"USE_OTP": False},
}
```

L'utilisateur peut se connecter en envoyant indifféremment son email ou son numéro dans le champ `username`. Pensez à garder `MultiFieldBackend` dans `AUTHENTICATION_BACKENDS` si vous utilisez aussi l'authentification Django standard (admin, par exemple).

### Scénario 4 — JWT uniquement en cookies httponly (pas de token dans le corps JSON)

```python
FORGE_AUTH = {
    "JWT": {"VIA_JSON": False, "VIA_HTTP_ONLY": True},
}
```

La réponse de `login` ne contient alors pas de corps JSON exploitable côté client JavaScript ; les cookies `access` et `refresh` sont posés directement par le serveur. Adapté à un frontend servi par le même domaine, qui n'a pas besoin de manipuler les tokens lui-même. Le cookie est marqué `secure` automatiquement dès que `DEBUG = False`.

### Scénario 5 — OTP par SMS, statut désactivé, OTP conservé

```python
FORGE_AUTH = {
    "OPTIONAL_FIELDS": ["status"],
    "OTP": {"OTP_CANAL": "SMS", "OTP_DIGITS": 6},
}
```

Le champ `status` (vérification/blocage de compte) disparaît du modèle, mais l'OTP reste actif avec un code à 6 chiffres. `OTP_CANAL` est une métadonnée que votre code applicatif peut lire (`forge_auth_config.otp_conf.OTP_CANAL`) pour choisir le bon prestataire d'envoi — voir "Points non automatisés".

### Scénario 6 — Auto-inscription par OTP (pas de formulaire d'inscription)

```python
FORGE_AUTH = {
    "REGISTER_INCLUDE_IN_OTP": True,
}
```

`POST /forge_auth/users/obtain-otp/` avec un numéro inconnu crée silencieusement l'utilisateur avant de générer le code, au lieu de renvoyer une erreur de validation. Utile pour un flux "connexion = inscription" piloté uniquement par numéro de téléphone.

## Endpoints de l'API

Chemins relatifs au préfixe `forge_auth/` exposé par `forge_auth.urls`.

| Méthode | Chemin | Action | Authentification requise |
|---|---|---|---|
| GET | `groups/` | Liste des groupes | Non |
| GET | `groups/{id}/` | Détail d'un groupe | Non |
| POST | `users/` | Inscription | Non |
| GET | `users/` | Liste des utilisateurs | Oui, staff uniquement |
| GET | `users/{id}/` | Détail d'un utilisateur | Oui, soi-même ou staff |
| PATCH / PUT | `users/{id}/` | Modification d'un utilisateur | Oui, soi-même ou staff |
| DELETE | `users/{id}/` | Suppression d'un utilisateur | Oui, soi-même ou staff |
| POST | `users/verify-email/` | Vérifie si un email existe déjà | Non |
| POST | `users/verify-phone/` | Vérifie si un téléphone existe déjà | Non |
| GET | `users/current/` | Utilisateur courant | Oui |
| POST | `users/login/` | Connexion (mot de passe ou OTP selon config) | Non |
| POST | `users/logout/` | Déconnexion (blackliste le refresh token) | Oui |
| GET | `users/session-check/` | Vérifie que la session/JWT est valide | Oui |
| POST | `users/refresh/` | Rafraîchit le token d'accès | Non (validé par le refresh token lui-même) |
| POST | `users/obtain-otp/` | Génère et stocke un code OTP | Non |
| POST | `users/authenticate-user/` | Étape 1 du flux F2FA (vérifie le mot de passe) | Non |
| POST | `users/verify-otp-and-login/` | Étape 2 du flux F2FA (vérifie l'OTP et connecte) | Non |
| POST | `users/change-password/` | Change son propre mot de passe (ancien mot de passe requis) | Oui |
| POST | `users/request-password-reset/` | Démarre le flux mot de passe oublié (génère un token) | Non |
| POST | `users/confirm-password-reset/` | Termine le flux mot de passe oublié (applique le nouveau mot de passe) | Non |

### Changement de mot de passe

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/change-password/ \
  -H "Authorization: Bearer <access>" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "ancien", "new_password": "nouveauMotDePasseSolide"}'
```

Le nouveau mot de passe est validé par `AUTH_PASSWORD_VALIDATORS` (settings Django standard). Les refresh tokens en cours sont blacklistés (si `rest_framework_simplejwt.token_blacklist` est installé) : les autres sessions ouvertes avec l'ancien mot de passe sont invalidées.

### Mot de passe oublié

Flux en deux étapes, basé sur `django.contrib.auth.tokens.default_token_generator` (stateless — aucun champ ni migration supplémentaire) :

```bash
# 1. Demande de réinitialisation : génère un token et envoie le signal
#    password_reset_requested (voir plus bas — l'envoi réel du token par
#    email/SMS est à la charge du projet hôte).
curl -X POST http://localhost:8000/api/forge_auth/users/request-password-reset/ \
  -H "Content-Type: application/json" \
  -d '{"username": "+225000000001"}'

# 2. Confirmation avec le token reçu (par email/SMS via le signal ci-dessus)
curl -X POST http://localhost:8000/api/forge_auth/users/confirm-password-reset/ \
  -H "Content-Type: application/json" \
  -d '{"username": "+225000000001", "token": "<token>", "new_password": "nouveauMotDePasseSolide"}'
```

Le token expire après `PASSWORD_RESET_TIMEOUT` (setting Django, 3 jours par défaut) et devient automatiquement invalide dès que le mot de passe change (il est dérivé du hash du mot de passe). Comme pour `change-password`, les refresh tokens en cours sont blacklistés après une réinitialisation réussie.

## Permissions : `IsSelfOrAdmin`

`forge_auth.permissions.IsSelfOrAdmin` (câblée dans `UserViewSet.get_permissions()`) empêche l'IDOR sur `/users/` :

- `list` : réservé aux utilisateurs avec `is_staff=True`.
- `retrieve` / `update` / `partial_update` / `destroy` : autorisés uniquement à l'utilisateur concerné (`obj.pk == request.user.pk`) ou à un membre du staff.

Sans cette permission, `IsAuthenticated` seul permettrait à n'importe quel utilisateur connecté de lire, modifier ou supprimer n'importe quel autre compte en changeant simplement le `{id}` dans l'URL.

## Throttling

Les actions sensibles (`login`, `authenticate-user`, `obtain-otp`, `verify-otp-and-login`, `refresh`, `request-password-reset`, `confirm-password-reset`) utilisent `forge_auth.throttling.ForgeAuthScopedRateThrottle`, une variante de `ScopedRateThrottle` de DRF qui **ne fait rien par défaut** : elle ne limite le débit d'une action que si son scope est explicitement configuré dans `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` du projet hôte (sinon `ImproperlyConfigured` planterait la requête, ce que `ForgeAuthScopedRateThrottle` évite).

Scopes utilisés :

| Scope | Actions concernées |
|---|---|
| `forge_auth_login` | `login`, `authenticate-user` |
| `forge_auth_otp` | `obtain-otp`, `verify-otp-and-login` |
| `forge_auth_refresh` | `refresh` |
| `forge_auth_password_reset` | `request-password-reset`, `confirm-password-reset` |

Exemple de configuration (voir aussi "Configuration rapide") :

```python
REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {
    "forge_auth_login": "10/min",
    "forge_auth_otp": "5/min",
    "forge_auth_refresh": "30/min",
    "forge_auth_password_reset": "5/min",
}
```

## Exemples d'utilisation

Inscription (scénario par défaut, téléphone) :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/ \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "+225000000001", "email": "alice@exemple.com"}'
```

Demande de code OTP :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/obtain-otp/ \
  -H "Content-Type: application/json" \
  -d '{"username": "+225000000001"}'
```

Connexion avec code OTP :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "+225000000001", "code": "1234"}'
```

Réponse (mode `JWT.VIA_JSON = True`) :

```json
{
  "access": "<jwt>",
  "refresh": "<jwt>",
  "user": {"pk": 1, "phone_number": "+225000000001", "email": "alice@exemple.com", "...": "..."}
}
```

Connexion avec mot de passe (OTP désactivé) :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "alice@exemple.com", "password": "motdepasse"}'
```

Appel authentifié (header) :

```bash
curl http://localhost:8000/api/forge_auth/users/current/ \
  -H "Authorization: Bearer <access>"
```

Rafraîchissement du token :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/refresh/ \
  -H "Authorization: Bearer <access>" \
  -H "Content-Type: application/json" \
  -d '{"refresh": "<refresh>"}'
```

Déconnexion :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/logout/ \
  -H "Authorization: Bearer <access>" \
  -H "Content-Type: application/json" \
  -d '{"refresh": "<refresh>"}'
```

Vérification d'unicité avant inscription (front-end) :

```bash
curl -X POST http://localhost:8000/api/forge_auth/users/verify-email/ \
  -H "Content-Type: application/json" \
  -d '{"verify": "alice@exemple.com"}'
```

## Modèle `User` : méthodes et propriétés utiles

- `user.username` : retourne la valeur du champ configuré comme `USERNAME_FIELD`.
- `user.full_name` : `"Prénom Nom"`.
- `user.is_valid_email` / `user.is_valid_phone_number` : validité syntaxique.
- `User.get(username)` : recherche sur `USERNAME_FIELD` et `ALTERNATIVE_USERNAME_FIELDS`, lève `User.DoesNotExist` ou `PermissionError` (compte au statut `deleted`, uniquement si `status` est activé).
- Si `status` est activé : `user.is_verified`, `user.is_unauthorized`, et les méthodes `mark_as_verified()`, `mark_as_unverified()`, `mark_as_suspended()`, `deactivate_user()`, `delete_user()`. `is_active=False` et `is_unauthorized` (statuts `blocked`/`suspended`/`deleted`/`deactivated`) sont tous les deux vérifiés par `login`, `authenticate-user` et `verify-otp-and-login` : un compte désactivé/bloqué/suspendu ne peut plus obtenir de nouveau JWT (401), même avec le bon mot de passe/code.
- Si `otp_secret` est activé et `OTP.USE_OTP` est `True` : `user.otp_token.generate_otp()` / `user.otp_token.verify_otp(code)`.

## Signal `user_logged_in`

`forge_auth.signals.user_logged_in` est un `django.dispatch.Signal` envoyé par `UserViewSet.login` juste après une authentification réussie (mot de passe ou OTP selon la config), avant que la réponse (JSON et/ou cookies JWT) ne soit renvoyée au client. Il permet au projet hôte de brancher des actions personnalisées (audit, notifications, mise à jour de métadonnées, etc.) sans avoir à surcharger la vue.

Arguments envoyés : `sender` (la classe `UserViewSet`), `request`, `user`.

```python
from django.dispatch import receiver
from forge_auth.signals import user_logged_in

@receiver(user_logged_in)
def on_forge_auth_login(sender, request, user, **kwargs):
    ...
```

Ce signal est spécifique à `forge_auth` (et distinct de `django.contrib.auth.signals.user_logged_in`) car l'authentification se fait via JWT et non via `django.contrib.auth.login()` / la session Django.

## Signal `otp_requested`

`forge_auth.signals.otp_requested` est envoyé par `UserViewSet.obtain_otp` juste après la génération d'un nouveau code OTP, avant que la réponse ne soit renvoyée au client. C'est le point d'extension prévu pour l'envoi effectif du code (SMS, WhatsApp, email...) — voir "Points non automatisés" ci-dessous.

Arguments envoyés : `sender` (la classe `UserViewSet`), `request`, `user`, `otp_token` (le code en clair est disponible via `otp_token.otp_code`).

```python
from django.dispatch import receiver
from forge_auth.signals import otp_requested

@receiver(otp_requested)
def on_forge_auth_otp_requested(sender, request, user, otp_token, **kwargs):
    send_sms(user.phone_number, otp_token.otp_code)
```

## Signal `password_reset_requested`

`forge_auth.signals.password_reset_requested` est envoyé par `UserViewSet.request_password_reset` juste après la génération d'un token de réinitialisation, avant que la réponse ne soit renvoyée au client. Même principe que `otp_requested` : c'est le point d'extension prévu pour l'envoi effectif du lien/code (email, SMS...) — voir "Points non automatisés" ci-dessous.

Arguments envoyés : `sender` (la classe `UserViewSet`), `request`, `user`, `token` (le token en clair, à inclure dans le lien envoyé à l'utilisateur — vérifié ensuite par `confirm-password-reset`).

```python
from django.dispatch import receiver
from forge_auth.signals import password_reset_requested

@receiver(password_reset_requested)
def on_forge_auth_password_reset_requested(sender, request, user, token, **kwargs):
    send_email(user.email, f"https://example.com/reset?username={user.username}&token={token}")
```

## Avertissement sur les migrations

Les migrations fournies (`0001_initial`, `0002_user_otp_secret_user_status`, `0003_otptoken`) ont été générées pour la configuration par défaut, c'est-à-dire `OPTIONAL_FIELDS = []` (les deux champs `status` et `otp_secret`, ainsi que le modèle `OtpToken`, existent en base).

`OPTIONAL_FIELDS` ne modifie que la classe Python `User` au chargement de l'application ; il ne régénère pas les migrations. Si vous changez `OPTIONAL_FIELDS` après avoir appliqué ces migrations sur une base existante, `makemigrations` détectera un écart (le modèle n'a plus les champs que les migrations ont créés) et vous devrez générer puis appliquer vos propres migrations de suppression. Si vous démarrez un projet neuf avec `OPTIONAL_FIELDS` déjà fixé, faites-le avant la toute première `migrate`, ou régénérez les migrations vous-même.

## Points non automatisés (à implémenter côté projet hôte)

Ces options de `FORGE_AUTH` sont validées au démarrage mais ne déclenchent aucune action automatique dans le code fourni :

- `OTP.OTP_CANAL` : `obtain-otp` génère et stocke le code (`otp_token.otp_code`), mais ne l'envoie nulle part. L'envoi effectif (SMS, WhatsApp, email) est à la charge du projet hôte, via le signal `otp_requested` (voir plus haut) ou en surchargeant l'action `obtain_otp`.
- `OTP.OTP_LIFETIME` : aucune expiration n'est vérifiée dans `verify_otp()`. À implémenter si nécessaire (comparaison avec `otp_token.updated_at`).
- Envoi du token de réinitialisation de mot de passe (`request-password-reset`) : le token est généré et disponible via le signal `password_reset_requested` (voir plus haut), mais rien ne l'envoie par email/SMS par défaut — à brancher côté projet hôte.

Automatisés (post_migrate, voir `signals.py`), malgré ce que suggérait une ancienne version de cette section :

- `CREDENTIALS_SUPERUSER` : un superutilisateur est créé automatiquement au premier `migrate` si aucun n'existe déjà (receiver `create_superuser`).
- `GROUPS` : les groupes listés sont créés automatiquement au `migrate` (receiver `initialize_groups`).
- `GROUP_DEFAULT` : assigné automatiquement à tout nouvel utilisateur créé sans `groups` explicite (`UserManager.create_user`).

## Notes de sécurité

- `OtpToken.verify_otp()` retourne toujours `True` lorsque `settings.DEBUG = True`, quel que soit le code fourni. Ne déployez jamais avec `DEBUG = True`.
- Les cookies JWT (`JWT.VIA_HTTP_ONLY`) sont posés avec `secure=True` dès que `DEBUG = False`. En développement local sans HTTPS, gardez `DEBUG = True` pour que les cookies soient acceptés par le navigateur.
- `rest_framework_simplejwt.token_blacklist` doit être dans `INSTALLED_APPS` pour que `logout`, `change-password` et `confirm-password-reset` puissent réellement blacklister les refresh tokens (sinon l'appel échoue silencieusement, capturé par un `except ImportError`/`except Exception: pass`).
- `/users/` est protégé par `IsSelfOrAdmin` (voir plus haut) : un utilisateur non-staff ne peut lister, consulter, modifier ou supprimer que son propre compte.
- `login`, `authenticate-user` et `verify-otp-and-login` vérifient `is_active` et `is_unauthorized` avant de délivrer un JWT : un compte désactivé/bloqué/suspendu/supprimé ne peut plus s'authentifier, même avec les bons identifiants.
- Aucun débit n'est limité par défaut (voir "Throttling") : configurez `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` pour vous protéger du brute force sur `login`/OTP/reset de mot de passe.
- La force du mot de passe n'est vérifiée (création, `change-password`, `confirm-password-reset`) que si `AUTH_PASSWORD_VALIDATORS` est configuré côté projet hôte (`[]` par défaut dans Django, donc aucune validation sans configuration explicite — voir "Configuration rapide").
- `change-password` et `confirm-password-reset` blacklistent les refresh tokens existants de l'utilisateur : les autres sessions ouvertes avec l'ancien mot de passe sont invalidées (nécessite `rest_framework_simplejwt.token_blacklist`, voir ci-dessus).

## Lancer les tests

```bash
uv sync --extra dev
uv run python -m pytest
```

(`python -m pytest` plutôt que `pytest` directement : garantit que le répertoire courant est sur `sys.path`, nécessaire pour que `tests.settings` s'importe.)

La configuration de test se trouve dans `tests/settings.py` et `tests/urls.py`. Organisation des tests, pour s'y retrouver :

| Fichier | Couvre |
|---|---|
| `tests/tests.py` | Endpoints DRF de bout en bout (déclaratif, via le package externe `django-forge-test` — `ForgeCase`/`ConfigForgeCase`, dépendance `dev`) : CRUD `users`/`groups`, login, logout, refresh, verify-email/phone, session-check. |
| `tests/test_conf.py` | Validation de `ForgeAuthConfig` (`conf.py`) : clés inconnues, types invalides, valeurs par défaut. |
| `tests/test_models.py` | `User`, `UserManager` (dont `GROUP_DEFAULT`), `StatusMixin`, `OtpToken`. |
| `tests/test_backends.py` | `MultiFieldBackend` (auth Django classique multi-champs). |
| `tests/test_authentication.py` | `JWTAuthenticationFlexible` (JWT via cookie et/ou header). |
| `tests/test_signals.py` | Signaux `user_logged_in`, `otp_requested`, et les receivers `post_migrate` (`create_superuser`, `initialize_groups`). |
| `tests/test_f2fa_views.py` | Flux F2FA (`authenticate-user`, `verify-otp-and-login`) : accès anonyme, échec fermé si OTP désactivé. |
| `tests/test_permissions.py` | `IsSelfOrAdmin` (IDOR sur `/users/`) et hachage du mot de passe sur `update()`. |
| `tests/test_login_security.py` | Blocage du login (`is_active`/`is_unauthorized`) pour les comptes désactivés/bloqués/suspendus/supprimés. |
| `tests/test_password_management.py` | `change-password`, `request-password-reset`, `confirm-password-reset`. |
| `tests/test_refresh.py` | `refresh` accessible sans authentification préalable, synchronisation du cookie `access`. |
| `tests/_helpers.py` | Utilitaires partagés (non collecté par pytest) : voir les docstrings pour les pièges de configuration en cours de test (`forge_auth_config.otp_conf`/`jwt_conf` figés au démarrage, non rafraîchis par `reset()`). |
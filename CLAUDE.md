# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ce que c'est

`forge-auth` (paquet PyPI `django-forge-auth`) est une **application Django réutilisable** (layout `src/`), pas un projet Django autonome. Elle fournit un système d'authentification complet et configurable : utilisateur personnalisé (avec photo de profil optionnelle), connexion par mot de passe, OTP, magic link ou OIDC, second facteur TOTP applicatif, JWT (header et/ou cookie httponly, avec rotation optionnelle), backend multi-champ, groupes/permissions, verrouillage de compte, gestion des sessions/appareils, historique de connexion, clés API M2M, et endpoints DRF prêts à l'emploi. Le code vit dans `src/forge_auth/`. `tests/` contient une app Django minimale (`tests/settings.py`, `tests/urls.py`) qui sert de projet hôte pour exécuter la suite de tests.

Le `README.md` est la référence exhaustive de toutes les options `FORGE_AUTH`, des scénarios de configuration, et des endpoints — le consulter avant de modifier le comportement configurable.

## Commandes

```bash
uv sync --extra dev                     # installe les dépendances (dont les extras dev)
uv run python -m pytest                 # lance la suite de tests (settings = tests.settings)
uv run python -m pytest tests/tests.py::UserTestCase::test_login_success   # un seul test
```

`python -m pytest` plutôt que `pytest` seul : ce dernier n'ajoute pas toujours le répertoire courant à `sys.path`, ce qui fait échouer l'import de `tests.settings`.

La suite de tests dépend du paquet externe `django-forge-test` (`forge_test.public.helpers.ForgeCase`, `forge_test.public.type.ConfigForgeCase`), déclaré en dépendance `dev` dans `pyproject.toml` (`>=0.8.0` — les versions antérieures ont un import circulaire interne). Sans lui, `tests/tests.py` ne peut pas s'importer.

Organisation des tests (`tests/`) : `tests.py` couvre les endpoints DRF de bout en bout via le DSL déclaratif `ForgeCase`/`ConfigForgeCase` ; tous les autres `test_*.py` sont des tests unitaires classiques (`django.test.TestCase`) par module/fonctionnalité — voir le tableau détaillé dans le README ("Lancer les tests") pour la liste complète (config, modèle/manager, backends, JWT flexible, signaux, F2FA, permissions/IDOR, sécurité du login, gestion de mot de passe, refresh/rotation, photo de profil, vérification de contact, verrouillage de compte, sessions, audit de connexion, suppression de compte, MFA TOTP, magic link, clés API, connexion sociale, throttling, i18n). `tests/_helpers.py` (non collecté par pytest) fournit des context managers pour contourner un piège de configuration en cours de test : voir "Configuration centralisée" ci-dessous. `tests/settings.py` définit `AUTH_PASSWORD_VALIDATORS` explicitement (Django ne le fait PAS par défaut, contrairement au settings.py généré par `startproject` : `[]` sans configuration) — nécessaire pour que les tests de validation de mot de passe (`change-password`, `confirm-password-reset`, update via `UserSerializer`) aient un effet — et `MEDIA_ROOT` pointant vers un répertoire temporaire (`tempfile.mkdtemp()`), pour que les tests de `profile_photo` n'écrivent jamais dans l'arbre du dépôt.

Pas de linter/formatter configuré dans ce dépôt.

## Architecture

### Configuration centralisée : `conf.py`

Tout le comportement de l'app est piloté par le dict `settings.FORGE_AUTH` du projet hôte, lu à travers le singleton `forge_auth_config` (instance de `ForgeAuthConfig` créée en bas de `conf.py`). C'est le point d'entrée à connaître avant de toucher à autre chose :

- `ForgeAuthConfig.validate()` est appelée dans `ForgeAuthConfig.ready()` (`apps.py`) au démarrage de Django. Une config invalide (clé inconnue, type incorrect, valeur hors énum) lève `ImproperlyConfigured` et arrête le serveur — voir la liste des erreurs possibles dans `conf.py`.
- `forge_auth_config.get(key)` peut être appelé avant `ready()` (ex. au moment de la définition de classes dans `models.py`/`admin.py`, qui s'exécute à l'import) : dans ce cas le cache `_resolved` se remplit paresseusement avec `_merge_conf()`, sans validation stricte.
- `reset()` vide le cache `_resolved` — utile dans les tests qui font `@override_settings(FORGE_AUTH=...)`. **Piège** : `reset()` ne rafraîchit PAS les attributs `otp_conf`, `jwt_conf`, `optional_fields`, `username_field`, `credentials_superuser_conf`, `register_include_in_otp`, `group_default`, `groups`, `account_lockout_conf`, `mfa_totp_conf`, `magic_link_conf`, matérialisés une seule fois dans `__init__`. Le code applicatif qui les lit comme attributs (`forge_auth_config.otp_conf.USE_OTP` dans `views.py`, `forge_auth_config.optional_fields` dans `models.py`/`serializers.py`...) reste donc figé à la config de démarrage même après `override_settings` + `reset()` ; seuls les appels `forge_auth_config.get(key)` explicites (utilisés par ex. dans `signals.py` pour `GROUPS`/`CREDENTIALS_SUPERUSER`, dans `models.py::UserManager.create_user` pour `GROUP_DEFAULT`, et dans `serializers.py::SocialLoginSerializer` pour `SOCIAL_AUTH`) sont réellement dynamiques. Voir `tests/_helpers.py` (`temporarily_disable_otp`, `forge_auth_override`) pour la façon de tester ces deux cas correctement — les tests des fonctionnalités "round 2" (lockout, MFA, magic link) mutent directement l'objet vivant (`forge_auth_config.account_lockout_conf.MAX_ATTEMPTS = ...`), même piège.
- **Bug connu** : `CREDENTIALS_SUPERUSER`/`OTP`/`JWT` sont convertis en objets (`CredentialSuperuserConf`/`OTPConf`/`JWTConf`) dès la construction de `ForgeAuthConfig` (dans `__init__`, avant tout appel à `validate()`). Un type invalide sur l'une de ces clés fait donc planter avec un `TypeError` brut au démarrage de Django plutôt que le message `ImproperlyConfigured` propre que `validate()` est censé produire — voir `tests/test_conf.py::ConstructionCrashesOnNonDictNestedConfigTestCase`.

### Le modèle `User` est construit dynamiquement à l'import

`models.py::_build_user_bases()` choisit les classes de base de `User` (`OtpSecretMixin`, `StatusMixin`, `ProfilePhotoMixin`) selon `FORGE_AUTH["OPTIONAL_FIELDS"]`, **au moment de l'import du module**. De même, `OtpToken` n'est une vraie classe Django (`models.Model`) que si `OTP.USE_OTP=True` et `otp_secret` n'est pas désactivé ; sinon c'est une classe factice qui lève `NotImplementedError` à l'instanciation, pour que les imports (`from forge_auth.models import OtpToken`) ne cassent jamais. `failed_login_attempts`/`locked_until` (verrouillage de compte) sont en revanche **toujours présents** sur `User`, pas conditionnés par `OPTIONAL_FIELDS` : légers, et la fonctionnalité elle-même se désactive via `ACCOUNT_LOCKOUT.MAX_ATTEMPTS = None`, pas en retirant le champ.

Conséquence directe : **les migrations fournies (`migrations/0001`–`0004`) sont figées pour la configuration par défaut** (`OPTIONAL_FIELDS=[]`, tous les champs présents en base). Changer `OPTIONAL_FIELDS` après coup sur une base existante désynchronise migrations et modèle — voir la section "Avertissement sur les migrations" du README avant toute modification touchant `OPTIONAL_FIELDS`, `USERNAME_FIELD` ou la structure du modèle `User`. `0004_...` a ajouté `profile_photo`/`failed_login_attempts`/`locked_until` sur `User`, ainsi que `ApiKey`, `SessionMetadata`, `LoginAuditLog`, `TotpDevice`, `TotpBackupCode`, `SocialAccount` (ces six modèles-là sont inconditionnels : ni FK vers un mixin optionnel, ni dépendance à `OPTIONAL_FIELDS`).

`admin.py` et `utils.py` suivent le même principe : les fieldsets/list_display de l'admin sont construits selon la config (`utils.py::build_fieldsets`/`build_list_display`), pas codés en dur.

### Modèles indépendants ajoutés en round 2 (`models.py`)

- `SessionMetadata` : stocke le `jti` du refresh token en simple `CharField` (**pas** de `ForeignKey` vers `rest_framework_simplejwt.token_blacklist.models.OutstandingToken`) — décision volontaire pour ne pas rendre ce modèle (et sa migration) dépendant de l'installation de `token_blacklist`. `revoke()` blackliste malgré tout le token correspondant si `token_blacklist` est disponible (recherche `OutstandingToken.objects.get(jti=...)`, best-effort). `views.py::_record_session`/`_sync_session_on_refresh` la tiennent à jour à `login`/`verify_otp_and_login`/`confirm_magic_link`/`social_login` (création) et `refresh` (mise à jour du jti si `JWT.ROTATE_REFRESH_TOKENS`).
- `LoginAuditLog` : `user` est `on_delete=SET_NULL, null=True` — un échec sur un identifiant inconnu doit rester tracé sans utilisateur réel rattaché (utile pour repérer un brute force). Écrit par `serializers.py::_log_login_attempt`, appelé à chaque point de sortie (succès/échec) de `LoginSerializer`/`LoginSerializerF2FA_STEP1`/`LoginSerializerF2FA_STEP2` — volontairement entouré d'un `except Exception` large : un problème d'écriture de l'audit log ne doit jamais faire échouer un login par ailleurs valide.
- `ApiKey` : la clé en clair n'est jamais stockée, seul son hash (`make_password`, même mécanisme que les mots de passe) l'est. `prefix` (12 premiers caractères de la clé en clair, non secret) sert uniquement à retrouver rapidement la ligne candidate en base (`authentification.py::ApiKeyAuthentication` filtre par `prefix` puis vérifie `check_password` sur ce petit sous-ensemble, pas sur toute la table).
- `TotpDevice`/`TotpBackupCode` : second facteur applicatif, **indépendant** de `OtpToken` (qui sert de méthode de connexion principale via `FORGE_AUTH["OTP"]`). `serializers.py::_verify_totp_if_enabled` est appelé après la vérification du mot de passe/OTP principal dans `LoginSerializer`/`LoginSerializerF2FA_STEP2` : si l'utilisateur a un `TotpDevice.confirmed=True`, un `totp_code` ou `backup_code` supplémentaire devient obligatoire.
- `SocialAccount` : la liaison se fait par `(provider, sub)`, jamais par email (un email peut changer ou ne pas être vérifié par le fournisseur). Voir `social.py` ci-dessous.

### Flux d'authentification, deux mécanismes séparés

- **Auth Django classique** (admin, `login()` Django) : `backends.py::MultiFieldBackend`, un `ModelBackend` qui accepte plusieurs champs d'identification (`USERNAME_FIELD` + `ALTERNATIVE_USERNAME_FIELDS`) via une requête `Q` dynamique avec `__iexact`.
- **Auth DRF/API** : `authentification.py::JWTAuthenticationFlexible`, qui étend `JWTAuthentication` de `simplejwt` et lit le token soit dans le cookie `access` (si `JWT.VIA_HTTP_ONLY`), soit dans le header `Authorization: Bearer` (si `JWT.VIA_JSON`) — les deux peuvent être actifs en même temps.

La logique métier de connexion (mot de passe vs OTP selon config, génération des tokens) est dans `serializers.py::LoginSerializer.validate()`, pas dans la vue. `views.py::UserViewSet.login` ne fait qu'appeler le serializer puis poser les cookies/JSON selon `forge_auth_config.jwt_conf`. `LoginSerializer`, `LoginSerializerF2FA_STEP1` et `LoginSerializerF2FA_STEP2` appellent tous `_ensure_account_usable(user)` juste avant de renvoyer l'utilisateur authentifié : ce helper vérifie `user.is_active` et `user.is_unauthorized` (si `status` est activé) et lève `AuthenticationFailed` sinon — nécessaire parce qu'aucun de ces flux ne passe par `django.contrib.auth.authenticate()` (qui ferait normalement cette vérification via `ModelBackend.user_can_authenticate`).

Ordre exact des vérifications dans ces trois serializers (important si on ajoute un nouveau facteur/contrôle) : `User.get()` → `_check_not_locked()` (verrouillage) → vérification mot de passe/OTP (avec `user.register_failed_login()`/`_log_login_attempt(..., FAILURE)` sur échec) → `_verify_totp_if_enabled()` (second facteur, seulement dans `LoginSerializer`/`STEP2`, pas `STEP1`) → `_ensure_account_usable()` (is_active/is_unauthorized) → `user.register_successful_login()` + `_log_login_attempt(..., SUCCESS)`. `STEP1` (`authenticate_user`) ne délivre aucun JWT : il réinitialise le compteur de lockout sur mot de passe correct mais n'écrit pas de `LoginAuditLog` "success" (seul `STEP2` le fait, car c'est lui qui complète réellement l'authentification F2FA).

### `signals.py` : automatisation post-migration et points d'extension

Deux receivers sur `post_migrate` : création d'un superutilisateur par défaut (`CREDENTIALS_SUPERUSER`, seulement s'il n'en existe aucun) et création des groupes listés dans `GROUPS`. `GROUP_DEFAULT` (assignation automatique d'un groupe par défaut aux nouveaux users) est câblé séparément, dans `models.py::UserManager.create_user` (pas un receiver `post_migrate` : ça se déclenche à chaque création d'utilisateur sans `groups` explicite, pas au `migrate`).

`signals.py` définit aussi cinq `django.dispatch.Signal`, tous sur le même principe (generation d'un artefact — code/token — puis envoi du signal, rien n'expédie l'artefact par défaut, c'est le point d'extension prévu) :
- `user_logged_in` (distinct de `django.contrib.auth.signals.user_logged_in`, car l'auth se fait en JWT et non via `django.contrib.auth.login()`) : envoyé par `login`/`verify_otp_and_login`/`confirm_magic_link`/`social_login` (`sender`, `request`, `user`) juste après authentification réussie, avant de construire la réponse.
- `otp_requested` : envoyé par `obtain_otp` (`sender`, `request`, `user`, `otp_token`).
- `password_reset_requested` : envoyé par `request_password_reset` (`sender`, `request`, `user`, `token` — `django.contrib.auth.tokens.default_token_generator`, stateless). Vérifié par `confirm_password_reset`.
- `contact_verification_requested` : envoyé par `request_contact_verification` (`sender`, `request`, `user`, `field` (`"email"`/`"phone_number"`), `token` — `django.core.signing.dumps(..., salt=serializers.CONTACT_VERIFICATION_SALT)`, encode aussi la valeur du champ pour invalider le token si elle change avant confirmation). Vérifié par `confirm_contact_verification`, qui bascule `status` à `verified`.
- `magic_link_requested` : envoyé par `request_magic_link` (`sender`, `request`, `user`, `token` — `signing.dumps({"pk": ...}, salt=serializers.MAGIC_LINK_SALT)`), actif seulement si `MAGIC_LINK.ENABLED=True` (405 sinon). Vérifié par `confirm_magic_link`, qui délivre un JWT comme `login`.

### Points explicitement non automatisés

Documentés dans le README ("Points non automatisés") : l'envoi effectif du code OTP (signal `otp_requested`), l'expiration du code OTP (`OTP.OTP_LIFETIME` n'est jamais vérifiée dans `OtpToken.verify_otp()`), et l'envoi effectif des tokens de réinitialisation de mot de passe / vérification de contact / magic link (signaux `password_reset_requested`/`contact_verification_requested`/`magic_link_requested`). Ne pas supposer que ces comportements existent déjà côté lib.

### Point de vigilance sécurité déjà connu

`OtpToken.verify_otp()` retourne toujours `True` quand `settings.DEBUG=True`, quel que soit le code fourni — comportement voulu pour le dev, dangereux si `DEBUG` traîne en prod côté projet hôte.

### Contrôle d'accès sur `/users/` (`permissions.py`)

`UserViewSet.get_permissions()` applique `permissions.py::IsSelfOrAdmin` (en plus de `IsAuthenticated`) à toute action non listée dans `public_actions` : `list` est réservé au staff, `retrieve`/`update`/`partial_update`/`destroy` sont réservés au propriétaire de l'objet ou au staff (`has_object_permission`). Avant l'ajout de cette permission, `IsAuthenticated` seul permettait à n'importe quel utilisateur connecté de lire/modifier/supprimer n'importe quel autre utilisateur (IDOR) — toute nouvelle action `detail=True` sur `UserViewSet` en hérite automatiquement via `get_permissions()`, sauf ajout explicite à `public_actions`.

**Nuance round 2** : les nouvelles actions `sessions`/`revoke-session`/`api-keys`/`create-api-key`/`revoke-api-key`/`login-history` sont toutes `detail=False` : `IsSelfOrAdmin.has_object_permission` ne s'applique donc jamais à elles (pas de `get_object()` sur `User`). L'isolation par utilisateur y est faite manuellement, à la main, dans chaque vue (`SessionMetadata.objects.filter(user=request.user, ...)`, `ApiKey.objects.filter(user=request.user, ...)`, etc.) — ne pas supposer que `IsSelfOrAdmin` protège ces sous-ressources, elle ne protège que `/users/{id}/`.

`UserViewSet.destroy()` est surchargé (avant l'appel à `super().destroy()`) pour exiger le mot de passe courant dans le corps de la requête quand `instance.pk == request.user.pk` (auto-suppression) — pas pour le staff supprimant un tiers.

### Throttling optionnel (`throttling.py`)

`throttling.py::ForgeAuthScopedRateThrottle` est une sous-classe de `ScopedRateThrottle` de DRF qui avale `ImproperlyConfigured` et renvoie `None` au lieu de planter quand le projet hôte n'a pas défini de débit pour un scope (`forge_auth_login`, `forge_auth_otp`, `forge_auth_refresh`, `forge_auth_password_reset`, `forge_auth_verify`) dans `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` — sans ça, une `ScopedRateThrottle` standard lève `ImproperlyConfigured` (500) au lieu de ne rien faire. `UserViewSet` déclare `throttle_scope = None` en attribut de classe : c'est nécessaire pour que `@action(..., throttle_scope=...)` fonctionne (DRF exige que tout kwarg passé à `@action` corresponde à un attribut déjà existant sur la classe).

**Piège de test DRF** (rencontré en écrivant `tests/test_throttling.py`) : `SimpleRateThrottle.THROTTLE_RATES = api_settings.DEFAULT_THROTTLE_RATES` est évalué **une seule fois**, à l'import du module `rest_framework.throttling` — `@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": ...})` dans un test ne suffit donc PAS à changer le débit effectif (le signal `setting_changed` de DRF ne retro-affecte pas cette classe attribute déjà figée). Pour tester un débit réellement appliqué, patcher directement `ForgeAuthScopedRateThrottle.THROTTLE_RATES` (avec restauration en `tearDown`/`addCleanup`), voir `tests/test_throttling.py::ThrottleAppliesWhenConfiguredTestCase`.

### Piège gettext_lazy : ne jamais assigner à une variable nommée `_`

`serializers.py` et `views.py` importent `from django.utils.translation import gettext_lazy as _`. Dans **n'importe quelle fonction de ces modules**, assigner une valeur à une variable nommée `_` (convention Python classique pour "valeur ignorée", ex. `_, created = Model.objects.get_or_create(...)`) rend `_` **local à toute la fonction** dès la compilation de son bytecode — même avant la ligne d'assignation. Un appel à `_("...")` plus haut dans la même fonction lève alors `UnboundLocalError: cannot access local variable '_'`, puisque Python la traite comme une variable locale non encore initialisée plutôt que comme le nom importé au niveau module. Repéré et corrigé sur `serializers.py::UsernameSerializer.validate_username` (`_, created = User.objects.get_or_create(...)` → renommé en `_user, created = ...`), couvert par régression dans `tests/test_i18n.py`. Avant d'ajouter un nouveau receveur ignoré (`_, x = ...`) dans une fonction qui traduit des messages, utiliser un autre nom (`_ignored`, ou le nom réel de la variable).

## Découverte des routes

`urls.py` monte un `DefaultRouter` DRF avec deux viewsets (`GroupViewSet` en lecture seule, `UserViewSet`) sous le préfixe `forge_auth/`. Toutes les actions custom sont des `@action` DRF dans `views.py`, documentées via `drf-spectacular` (`@extend_schema`) :

- Connexion/session : `login`, `logout`, `refresh`, `session-check`, `authenticate-user`, `verify-otp-and-login`, `obtain-otp`, `request-magic-link`, `confirm-magic-link`, `social-login`.
- Compte : `current`, `verify-email`, `verify-phone`, `change-password`, `request-password-reset`, `confirm-password-reset`, `request-contact-verification`, `confirm-contact-verification`.
- MFA : `mfa-totp-setup`, `mfa-totp-confirm`, `mfa-totp-disable`.
- Sessions/audit : `sessions`, `revoke-session`, `login-history`.
- Clés API : `api-keys`, `create-api-key`, `revoke-api-key`.

`UserViewSet.get_permissions()` liste explicitement les actions publiques (`public_actions`, voir la constante dans `views.py`) ; toute nouvelle action doit être classée consciemment public/authentifié à cet endroit — les actions authentifiées `detail=True` (`retrieve`/`update`/`destroy`) héritent aussi de `IsSelfOrAdmin` (voir ci-dessus), les `detail=False` n'en héritent que pour `list` et doivent filtrer `request.user` elles-mêmes si elles exposent une sous-ressource par utilisateur.

## Module `social.py` : vérification OIDC

`social.py::verify_id_token(id_token, *, issuer, audience)` fait un appel réseau réel (`urllib.request` vers `{issuer}/.well-known/openid-configuration` pour découvrir `jwks_uri`, puis `jwt.PyJWKClient` pour récupérer les clés publiques et `jwt.decode(..., algorithms=["RS256"])` pour vérifier signature/`iss`/`aud`). C'est volontairement le **seul point d'entrée à mocker dans les tests** (`unittest.mock.patch("forge_auth.social.verify_id_token")`, voir `tests/test_social_auth.py`) : simuler un vrai fournisseur OAuth dans une suite de tests unitaires n'a pas de sens. `serializers.py::SocialLoginSerializer` appelle `social.verify_id_token(...)` (import du module, pas `from ... import verify_id_token`, pour que le monkeypatch fonctionne de façon fiable) et lit `FORGE_AUTH["SOCIAL_AUTH"][provider]` (dict `{ISSUER, CLIENT_ID}`) de façon dynamique via `forge_auth_config.get(...)`.

Dépendance : `pyjwt[crypto]` (le extra `crypto` installe `cryptography`, nécessaire pour vérifier des signatures RS256 — la plupart des fournisseurs OIDC n'utilisent pas HS256).

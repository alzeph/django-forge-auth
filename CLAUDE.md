# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ce que c'est

`forge-auth` (paquet PyPI `django-forge-auth`) est une **application Django réutilisable** (layout `src/`), pas un projet Django autonome. Elle fournit un système d'authentification complet et configurable : utilisateur personnalisé, connexion par mot de passe ou OTP, JWT (header et/ou cookie httponly), backend multi-champ, groupes/permissions, endpoints DRF prêts à l'emploi. Le code vit dans `src/forge_auth/`. `tests/` contient une app Django minimale (`tests/settings.py`, `tests/urls.py`) qui sert de projet hôte pour exécuter la suite de tests.

Le `README.md` est la référence exhaustive de toutes les options `FORGE_AUTH`, des scénarios de configuration, et des endpoints — le consulter avant de modifier le comportement configurable.

## Commandes

```bash
uv sync --extra dev                     # installe les dépendances (dont les extras dev)
uv run python -m pytest                 # lance la suite de tests (settings = tests.settings)
uv run python -m pytest tests/tests.py::UserTestCase::test_login_success   # un seul test
```

`python -m pytest` plutôt que `pytest` seul : ce dernier n'ajoute pas toujours le répertoire courant à `sys.path`, ce qui fait échouer l'import de `tests.settings`.

La suite de tests dépend du paquet externe `django-forge-test` (`forge_test.public.helpers.ForgeCase`, `forge_test.public.type.ConfigForgeCase`), déclaré en dépendance `dev` dans `pyproject.toml` (`>=0.8.0` — les versions antérieures ont un import circulaire interne). Sans lui, `tests/tests.py` ne peut pas s'importer.

Organisation des tests (`tests/`) : `tests.py` couvre les endpoints DRF de bout en bout via le DSL déclaratif `ForgeCase`/`ConfigForgeCase` ; `test_conf.py`, `test_models.py`, `test_backends.py`, `test_authentication.py`, `test_signals.py`, `test_f2fa_views.py`, `test_permissions.py`, `test_login_security.py`, `test_password_management.py`, `test_refresh.py` sont des tests unitaires classiques (`django.test.TestCase`) par module — voir le tableau détaillé dans le README ("Lancer les tests"). `tests/_helpers.py` (non collecté par pytest) fournit des context managers pour contourner un piège de configuration en cours de test : voir "Configuration centralisée" ci-dessous. `tests/settings.py` définit `AUTH_PASSWORD_VALIDATORS` explicitement (Django ne le fait PAS par défaut, contrairement au settings.py généré par `startproject` : `[]` sans configuration) — nécessaire pour que les tests de validation de mot de passe (`change-password`, `confirm-password-reset`, update via `UserSerializer`) aient un effet.

Pas de linter/formatter configuré dans ce dépôt.

## Architecture

### Configuration centralisée : `conf.py`

Tout le comportement de l'app est piloté par le dict `settings.FORGE_AUTH` du projet hôte, lu à travers le singleton `forge_auth_config` (instance de `ForgeAuthConfig` créée en bas de `conf.py`). C'est le point d'entrée à connaître avant de toucher à autre chose :

- `ForgeAuthConfig.validate()` est appelée dans `ForgeAuthConfig.ready()` (`apps.py`) au démarrage de Django. Une config invalide (clé inconnue, type incorrect, valeur hors énum) lève `ImproperlyConfigured` et arrête le serveur — voir la liste des erreurs possibles dans `conf.py`.
- `forge_auth_config.get(key)` peut être appelé avant `ready()` (ex. au moment de la définition de classes dans `models.py`/`admin.py`, qui s'exécute à l'import) : dans ce cas le cache `_resolved` se remplit paresseusement avec `_merge_conf()`, sans validation stricte.
- `reset()` vide le cache `_resolved` — utile dans les tests qui font `@override_settings(FORGE_AUTH=...)`. **Piège** : `reset()` ne rafraîchit PAS les attributs `otp_conf`, `jwt_conf`, `optional_fields`, `username_field`, `credentials_superuser_conf`, `register_include_in_otp`, `group_default`, `groups`, matérialisés une seule fois dans `__init__`. Le code applicatif qui les lit comme attributs (`forge_auth_config.otp_conf.USE_OTP` dans `views.py`, `forge_auth_config.optional_fields` dans `models.py`/`serializers.py`...) reste donc figé à la config de démarrage même après `override_settings` + `reset()` ; seuls les appels `forge_auth_config.get(key)` explicites (utilisés par ex. dans `signals.py` pour `GROUPS`/`CREDENTIALS_SUPERUSER`, et dans `models.py::UserManager.create_user` pour `GROUP_DEFAULT`) sont réellement dynamiques. Voir `tests/_helpers.py` (`temporarily_disable_otp`, `forge_auth_override`) pour la façon de tester ces deux cas correctement.
- **Bug connu** : `CREDENTIALS_SUPERUSER`/`OTP`/`JWT` sont convertis en objets (`CredentialSuperuserConf`/`OTPConf`/`JWTConf`) dès la construction de `ForgeAuthConfig` (dans `__init__`, avant tout appel à `validate()`). Un type invalide sur l'une de ces clés fait donc planter avec un `TypeError` brut au démarrage de Django plutôt que le message `ImproperlyConfigured` propre que `validate()` est censé produire — voir `tests/test_conf.py::ConstructionCrashesOnNonDictNestedConfigTestCase`.

### Le modèle `User` est construit dynamiquement à l'import

`models.py::_build_user_bases()` choisit les classes de base de `User` (`OtpSecretMixin`, `StatusMixin`) selon `FORGE_AUTH["OPTIONAL_FIELDS"]`, **au moment de l'import du module**. De même, `OtpToken` n'est une vraie classe Django (`models.Model`) que si `OTP.USE_OTP=True` et `otp_secret` n'est pas désactivé ; sinon c'est une classe factice qui lève `NotImplementedError` à l'instanciation, pour que les imports (`from forge_auth.models import OtpToken`) ne cassent jamais.

Conséquence directe : **les migrations fournies (`migrations/0001`–`0003`) sont figées pour la configuration par défaut** (`OPTIONAL_FIELDS=[]`, tous les champs présents en base). Changer `OPTIONAL_FIELDS` après coup sur une base existante désynchronise migrations et modèle — voir la section "Avertissement sur les migrations" du README avant toute modification touchant `OPTIONAL_FIELDS`, `USERNAME_FIELD` ou la structure du modèle `User`.

`admin.py` et `utils.py` suivent le même principe : les fieldsets/list_display de l'admin sont construits selon la config (`utils.py::build_fieldsets`/`build_list_display`), pas codés en dur.

### Flux d'authentification, deux mécanismes séparés

- **Auth Django classique** (admin, `login()` Django) : `backends.py::MultiFieldBackend`, un `ModelBackend` qui accepte plusieurs champs d'identification (`USERNAME_FIELD` + `ALTERNATIVE_USERNAME_FIELDS`) via une requête `Q` dynamique avec `__iexact`.
- **Auth DRF/API** : `authentification.py::JWTAuthenticationFlexible`, qui étend `JWTAuthentication` de `simplejwt` et lit le token soit dans le cookie `access` (si `JWT.VIA_HTTP_ONLY`), soit dans le header `Authorization: Bearer` (si `JWT.VIA_JSON`) — les deux peuvent être actifs en même temps.

La logique métier de connexion (mot de passe vs OTP selon config, génération des tokens) est dans `serializers.py::LoginSerializer.validate()`, pas dans la vue. `views.py::UserViewSet.login` ne fait qu'appeler le serializer puis poser les cookies/JSON selon `forge_auth_config.jwt_conf`. `LoginSerializer`, `LoginSerializerF2FA_STEP1` et `LoginSerializerF2FA_STEP2` appellent tous `_ensure_account_usable(user)` juste avant de renvoyer l'utilisateur authentifié : ce helper vérifie `user.is_active` et `user.is_unauthorized` (si `status` est activé) et lève `AuthenticationFailed` sinon — nécessaire parce qu'aucun de ces flux ne passe par `django.contrib.auth.authenticate()` (qui ferait normalement cette vérification via `ModelBackend.user_can_authenticate`).

### `signals.py` : automatisation post-migration et points d'extension

Deux receivers sur `post_migrate` : création d'un superutilisateur par défaut (`CREDENTIALS_SUPERUSER`, seulement s'il n'en existe aucun) et création des groupes listés dans `GROUPS`. `GROUP_DEFAULT` (assignation automatique d'un groupe par défaut aux nouveaux users) est câblé séparément, dans `models.py::UserManager.create_user` (pas un receiver `post_migrate` : ça se déclenche à chaque création d'utilisateur sans `groups` explicite, pas au `migrate`).

`signals.py` définit aussi trois `django.dispatch.Signal` :
- `user_logged_in` (distinct de `django.contrib.auth.signals.user_logged_in`, car l'auth se fait en JWT et non via `django.contrib.auth.login()`) : envoyé par `views.py::UserViewSet.login` (`sender`, `request`, `user`) juste après authentification réussie, avant de construire la réponse.
- `otp_requested` : envoyé par `views.py::UserViewSet.obtain_otp` (`sender`, `request`, `user`, `otp_token`) juste après génération d'un code OTP — c'est le point d'extension attendu pour brancher l'envoi effectif (SMS/WhatsApp/email), voir "Points explicitement non automatisés" ci-dessous.
- `password_reset_requested` : envoyé par `views.py::UserViewSet.request_password_reset` (`sender`, `request`, `user`, `token`) juste après génération d'un token de réinitialisation (`django.contrib.auth.tokens.default_token_generator`, stateless — pas de champ/migration dédié). Même principe que `otp_requested` : rien n'envoie le token par défaut, c'est le point d'extension prévu pour ça. Le token est vérifié par `views.py::UserViewSet.confirm_password_reset`.

### Points explicitement non automatisés

Documentés dans le README ("Points non automatisés") : l'envoi effectif du code OTP (`OTP.OTP_CANAL` n'est qu'une métadonnée lisible via `forge_auth_config.otp_conf.OTP_CANAL` — le signal `otp_requested` est le point d'extension prévu pour le brancher, mais rien n'envoie le code par défaut), l'expiration du code (`OTP.OTP_LIFETIME` n'est jamais vérifiée dans `OtpToken.verify_otp()`), et l'envoi effectif du token de réinitialisation de mot de passe (signal `password_reset_requested`, même principe que `otp_requested`). Ne pas supposer que ces comportements existent déjà côté lib.

### Point de vigilance sécurité déjà connu

`OtpToken.verify_otp()` retourne toujours `True` quand `settings.DEBUG=True`, quel que soit le code fourni — comportement voulu pour le dev, dangereux si `DEBUG` traîne en prod côté projet hôte.

### Contrôle d'accès sur `/users/` (`permissions.py`)

`UserViewSet.get_permissions()` applique `permissions.py::IsSelfOrAdmin` (en plus de `IsAuthenticated`) à toute action non listée dans `public_actions` : `list` est réservé au staff, `retrieve`/`update`/`partial_update`/`destroy` sont réservés au propriétaire de l'objet ou au staff (`has_object_permission`). Avant l'ajout de cette permission, `IsAuthenticated` seul permettait à n'importe quel utilisateur connecté de lire/modifier/supprimer n'importe quel autre utilisateur (IDOR) — toute nouvelle action `detail=True` sur `UserViewSet` en hérite automatiquement via `get_permissions()`, sauf ajout explicite à `public_actions`.

### Throttling optionnel (`throttling.py`)

`throttling.py::ForgeAuthScopedRateThrottle` est une sous-classe de `ScopedRateThrottle` de DRF qui avale `ImproperlyConfigured` et renvoie `None` au lieu de planter quand le projet hôte n'a pas défini de débit pour un scope (`forge_auth_login`, `forge_auth_otp`, `forge_auth_refresh`, `forge_auth_password_reset`) dans `REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]` — sans ça, une `ScopedRateThrottle` standard lève `ImproperlyConfigured` (500) au lieu de ne rien faire. `UserViewSet` déclare `throttle_scope = None` en attribut de classe : c'est nécessaire pour que `@action(..., throttle_scope=...)` fonctionne (DRF exige que tout kwarg passé à `@action` corresponde à un attribut déjà existant sur la classe).

## Découverte des routes

`urls.py` monte un `DefaultRouter` DRF avec deux viewsets (`GroupViewSet` en lecture seule, `UserViewSet`) sous le préfixe `forge_auth/`. Toutes les actions custom (`login`, `logout`, `refresh`, `session-check`, `obtain-otp`, `verify-email`, `verify-phone`, `current`, `authenticate-user`, `verify-otp-and-login`, `change-password`, `request-password-reset`, `confirm-password-reset`) sont des `@action` DRF dans `views.py`, documentées via `drf-spectacular` (`@extend_schema`). `UserViewSet.get_permissions()` liste explicitement les actions publiques (`create`, `obtain_otp`, `verify_email`, `verify_phone`, `login`, `authenticate_user`, `verify_otp_and_login`, `refresh`, `request_password_reset`, `confirm_password_reset`) ; toute nouvelle action doit être classée consciemment public/authentifié à cet endroit — les actions authentifiées héritent aussi de `IsSelfOrAdmin` (voir ci-dessus), pas seulement de `IsAuthenticated`.

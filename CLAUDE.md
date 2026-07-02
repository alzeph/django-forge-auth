# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ce que c'est

`forge-auth` (paquet PyPI `django-forge-auth`) est une **application Django réutilisable** (layout `src/`), pas un projet Django autonome. Elle fournit un système d'authentification complet et configurable : utilisateur personnalisé, connexion par mot de passe ou OTP, JWT (header et/ou cookie httponly), backend multi-champ, groupes/permissions, endpoints DRF prêts à l'emploi. Le code vit dans `src/forge_auth/`. `tests/` contient une app Django minimale (`tests/settings.py`, `tests/urls.py`) qui sert de projet hôte pour exécuter la suite de tests.

Le `README.md` est la référence exhaustive de toutes les options `FORGE_AUTH`, des scénarios de configuration, et des endpoints — le consulter avant de modifier le comportement configurable.

## Commandes

```bash
uv sync                # installe les dépendances (dont les extras dev)
uv run pytest          # lance la suite de tests (settings = tests.settings)
uv run pytest tests/tests.py::UserTestCase::test_login_success   # un seul test
```

La suite de tests dépend du paquet externe `django-forge-test` (`forge_test.public.helpers.ForgeCase`, `ConfigForgeCase`), déclaré en dépendance `dev` dans `pyproject.toml`. Sans lui, `tests/tests.py` ne peut pas s'importer.

Pas de linter/formatter configuré dans ce dépôt.

## Architecture

### Configuration centralisée : `conf.py`

Tout le comportement de l'app est piloté par le dict `settings.FORGE_AUTH` du projet hôte, lu à travers le singleton `forge_auth_config` (instance de `ForgeAuthConfig` créée en bas de `conf.py`). C'est le point d'entrée à connaître avant de toucher à autre chose :

- `ForgeAuthConfig.validate()` est appelée dans `ForgeAuthConfig.ready()` (`apps.py`) au démarrage de Django. Une config invalide (clé inconnue, type incorrect, valeur hors énum) lève `ImproperlyConfigured` et arrête le serveur — voir la liste des erreurs possibles dans `conf.py`.
- `forge_auth_config.get(key)` peut être appelé avant `ready()` (ex. au moment de la définition de classes dans `models.py`/`admin.py`, qui s'exécute à l'import) : dans ce cas le cache `_resolved` se remplit paresseusement avec `_merge_conf()`, sans validation stricte.
- `reset()` vide le cache — utile dans les tests qui font `@override_settings(FORGE_AUTH=...)`.

### Le modèle `User` est construit dynamiquement à l'import

`models.py::_build_user_bases()` choisit les classes de base de `User` (`OtpSecretMixin`, `StatusMixin`) selon `FORGE_AUTH["OPTIONAL_FIELDS"]`, **au moment de l'import du module**. De même, `OtpToken` n'est une vraie classe Django (`models.Model`) que si `OTP.USE_OTP=True` et `otp_secret` n'est pas désactivé ; sinon c'est une classe factice qui lève `NotImplementedError` à l'instanciation, pour que les imports (`from forge_auth.models import OtpToken`) ne cassent jamais.

Conséquence directe : **les migrations fournies (`migrations/0001`–`0003`) sont figées pour la configuration par défaut** (`OPTIONAL_FIELDS=[]`, tous les champs présents en base). Changer `OPTIONAL_FIELDS` après coup sur une base existante désynchronise migrations et modèle — voir la section "Avertissement sur les migrations" du README avant toute modification touchant `OPTIONAL_FIELDS`, `USERNAME_FIELD` ou la structure du modèle `User`.

`admin.py` et `utils.py` suivent le même principe : les fieldsets/list_display de l'admin sont construits selon la config (`utils.py::build_fieldsets`/`build_list_display`), pas codés en dur.

### Flux d'authentification, deux mécanismes séparés

- **Auth Django classique** (admin, `login()` Django) : `backends.py::MultiFieldBackend`, un `ModelBackend` qui accepte plusieurs champs d'identification (`USERNAME_FIELD` + `ALTERNATIVE_USERNAME_FIELDS`) via une requête `Q` dynamique avec `__iexact`.
- **Auth DRF/API** : `authentification.py::JWTAuthenticationFlexible`, qui étend `JWTAuthentication` de `simplejwt` et lit le token soit dans le cookie `access` (si `JWT.VIA_HTTP_ONLY`), soit dans le header `Authorization: Bearer` (si `JWT.VIA_JSON`) — les deux peuvent être actifs en même temps.

La logique métier de connexion (mot de passe vs OTP selon config, génération des tokens) est dans `serializers.py::LoginSerializer.validate()`, pas dans la vue. `views.py::UserViewSet.login` ne fait qu'appeler le serializer puis poser les cookies/JSON selon `forge_auth_config.jwt_conf`.

### `signals.py` : automatisation post-migration et point d'extension à la connexion

Deux receivers sur `post_migrate` : création d'un superutilisateur par défaut (`CREDENTIALS_SUPERUSER`, seulement s'il n'en existe aucun) et création des groupes listés dans `GROUPS`. `GROUP_DEFAULT` (assignation automatique d'un groupe par défaut aux nouveaux users) n'est en revanche pas encore câblé.

`signals.py` définit aussi deux `django.dispatch.Signal` :
- `user_logged_in` (distinct de `django.contrib.auth.signals.user_logged_in`, car l'auth se fait en JWT et non via `django.contrib.auth.login()`) : envoyé par `views.py::UserViewSet.login` (`sender`, `request`, `user`) juste après authentification réussie, avant de construire la réponse.
- `otp_requested` : envoyé par `views.py::UserViewSet.obtain_otp` (`sender`, `request`, `user`, `otp_token`) juste après génération d'un code OTP — c'est le point d'extension attendu pour brancher l'envoi effectif (SMS/WhatsApp/email), voir "Points explicitement non automatisés" ci-dessous.

### Points explicitement non automatisés

Documentés dans le README ("Points non automatisés") : l'envoi effectif du code OTP (`OTP.OTP_CANAL` n'est qu'une métadonnée lisible via `forge_auth_config.otp_conf.OTP_CANAL` — le signal `otp_requested` est le point d'extension prévu pour le brancher, mais rien n'envoie le code par défaut) et l'expiration du code (`OTP.OTP_LIFETIME` n'est jamais vérifiée dans `OtpToken.verify_otp()`). Ne pas supposer que ces comportements existent déjà côté lib.

### Point de vigilance sécurité déjà connu

`OtpToken.verify_otp()` retourne toujours `True` quand `settings.DEBUG=True`, quel que soit le code fourni — comportement voulu pour le dev, dangereux si `DEBUG` traîne en prod côté projet hôte.

## Découverte des routes

`urls.py` monte un `DefaultRouter` DRF avec deux viewsets (`GroupViewSet` en lecture seule, `UserViewSet`) sous le préfixe `forge_auth/`. Toutes les actions custom (`login`, `logout`, `refresh`, `session-check`, `obtain-otp`, `verify-email`, `verify-phone`, `current`) sont des `@action` DRF dans `views.py`, documentées via `drf-spectacular` (`@extend_schema`). `UserViewSet.get_permissions()` liste explicitement les actions publiques (`create`, `obtain_otp`, `verify_email`, `verify_phone`, `login`) ; toute nouvelle action doit être classée consciemment public/authentifié à cet endroit.

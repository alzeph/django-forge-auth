"""
Tests de IsSelfOrAdmin (src/forge_auth/permissions.py) et de son câblage
dans UserViewSet.get_permissions() (src/forge_auth/views.py).

Régression : avant ce correctif, UserViewSet n'avait que
`permissions.IsAuthenticated`, sans aucune vérification d'objet. N'importe
quel utilisateur connecté pouvait donc lister/consulter/modifier/supprimer
N'IMPORTE QUEL AUTRE utilisateur via /forge_auth/users/{pk}/ (IDOR).
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class UserListIsStaffOnlyTestCase(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(phone_number="+225000000200", password="qwerty123", is_staff=True)
        self.regular = User.objects.create_user(phone_number="+225000000201", password="qwerty123")

    def test_staff_can_list_users(self):
        response = _client_for(self.staff).get(reverse("forge_auth:users-list"))
        self.assertEqual(response.status_code, 200)

    def test_regular_user_cannot_list_users(self):
        response = _client_for(self.regular).get(reverse("forge_auth:users-list"))
        self.assertEqual(response.status_code, 403)

    def test_anonymous_cannot_list_users(self):
        response = APIClient().get(reverse("forge_auth:users-list"))
        self.assertEqual(response.status_code, 401)


class UserDetailIDORTestCase(TestCase):
    """
    Avant le fix : un utilisateur authentifié pouvait consulter/modifier/
    supprimer n'importe quel autre utilisateur en changeant simplement le
    {pk} de l'URL.
    """

    def setUp(self):
        self.alice = User.objects.create_user(phone_number="+225000000210", password="qwerty123")
        self.bob = User.objects.create_user(phone_number="+225000000211", password="qwerty123")
        self.staff = User.objects.create_user(phone_number="+225000000212", password="qwerty123", is_staff=True)

    def test_user_can_retrieve_own_detail(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.alice.pk})
        response = _client_for(self.alice).get(url)
        self.assertEqual(response.status_code, 200)

    def test_user_cannot_retrieve_another_users_detail(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.bob.pk})
        response = _client_for(self.alice).get(url)
        self.assertEqual(response.status_code, 403)

    def test_staff_can_retrieve_any_user_detail(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.alice.pk})
        response = _client_for(self.staff).get(url)
        self.assertEqual(response.status_code, 200)

    def test_user_cannot_update_another_user(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.bob.pk})
        response = _client_for(self.alice).patch(url, {"first_name": "Hacked"}, format="json")
        self.assertEqual(response.status_code, 403)
        self.bob.refresh_from_db()
        self.assertNotEqual(self.bob.first_name, "Hacked")

    def test_user_can_update_own_profile(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.alice.pk})
        response = _client_for(self.alice).patch(url, {"first_name": "Alice"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.alice.refresh_from_db()
        self.assertEqual(self.alice.first_name, "Alice")

    def test_user_cannot_delete_another_user(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.bob.pk})
        response = _client_for(self.alice).delete(url)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.bob.pk).exists())

    def test_staff_can_delete_another_user(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.bob.pk})
        response = _client_for(self.staff).delete(url)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(User.objects.filter(pk=self.bob.pk).exists())


class UserUpdatePasswordHashingTestCase(TestCase):
    """
    Régression : `UserSerializer` n'avait pas de `update()` propre.
    `ModelSerializer.update()` fait `setattr(instance, "password", value)` +
    `save()`, sans passer par `set_password()` : un PATCH avec un mot de
    passe l'écrivait donc EN CLAIR en base.
    """

    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000000220", password="qwerty123")

    def test_patching_password_hashes_it(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.user.pk})
        response = _client_for(self.user).patch(url, {"password": "N3wStrongPassw0rd!"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.password, "N3wStrongPassw0rd!")
        self.assertTrue(self.user.check_password("N3wStrongPassw0rd!"))

    def test_weak_password_on_update_is_rejected(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.user.pk})
        response = _client_for(self.user).patch(url, {"password": "123"}, format="json")
        self.assertEqual(response.status_code, 400)

"""
Tests de la confirmation par mot de passe avant suppression de compte :
src/forge_auth/views.py::UserViewSet.destroy.
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


class SelfDeletionRequiresPasswordTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000001600", password="qwerty123")
        self.client_auth = _client_for(self.user)
        self.url = reverse("forge_auth:users-detail", kwargs={"pk": self.user.pk})

    def test_delete_without_password_is_rejected(self):
        response = self.client_auth.delete(self.url)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_delete_with_wrong_password_is_rejected(self):
        response = self.client_auth.delete(self.url, {"password": "wrong"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_delete_with_correct_password_succeeds(self):
        response = self.client_auth.delete(self.url, {"password": "qwerty123"}, format="json")
        self.assertEqual(response.status_code, 204)
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())


class StaffDeletionDoesNotRequirePasswordTestCase(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(phone_number="+225000001601", password="qwerty123", is_staff=True)
        self.target = User.objects.create_user(phone_number="+225000001602", password="qwerty123")
        self.staff_client = _client_for(self.staff)

    def test_staff_deletes_another_user_without_password(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.target.pk})
        response = self.staff_client.delete(url)
        self.assertEqual(response.status_code, 204)
        self.assertFalse(User.objects.filter(pk=self.target.pk).exists())

    def test_staff_self_deletion_still_requires_password(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.staff.pk})
        response = self.staff_client.delete(url)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.staff.pk).exists())

"""
Tests du champ optionnel `profile_photo` (src/forge_auth/models.py::
ProfilePhotoMixin), activé par défaut (OPTIONAL_FIELDS=[]).
"""
import io

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from PIL import Image
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


def _tiny_png() -> SimpleUploadedFile:
    # Généré via Pillow (déjà une dépendance de forge_auth pour ImageField) :
    # garantit un PNG 1x1 réellement valide, pas juste une extension .png.
    buffer = io.BytesIO()
    Image.new("RGB", (1, 1), color="red").save(buffer, format="PNG")
    return SimpleUploadedFile("avatar.png", buffer.getvalue(), content_type="image/png")


def _client_for(user) -> APIClient:
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return client


class ProfilePhotoTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(phone_number="+225000001300", password="qwerty123")
        self.client_auth = _client_for(self.user)

    def test_field_present_and_null_by_default(self):
        response = self.client_auth.get(reverse("forge_auth:users-current"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("profile_photo", response.data)
        self.assertIsNone(response.data["profile_photo"])

    def test_upload_via_patch(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.user.pk})
        response = self.client_auth.patch(url, {"profile_photo": _tiny_png()}, format="multipart")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.data["profile_photo"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.profile_photo.name)
        self.user.profile_photo.delete(save=True)

    def test_rejects_non_image_file(self):
        url = reverse("forge_auth:users-detail", kwargs={"pk": self.user.pk})
        bad_file = SimpleUploadedFile("not-an-image.png", b"this is not a real png", content_type="image/png")
        response = self.client_auth.patch(url, {"profile_photo": bad_file}, format="multipart")
        self.assertEqual(response.status_code, 400)

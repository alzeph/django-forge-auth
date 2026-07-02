from django.utils.translation import gettext_lazy as _

from forge_auth.conf import forge_auth_config


def build_fieldsets():
    username_field = forge_auth_config.get("USERNAME_FIELD")
    personal_fields = ["first_name", "last_name"]

    extra_fields = []
    if forge_auth_config.is_enabled_field("status"):
        extra_fields.append("status")

    status_fields = ["is_active", "is_staff", "is_superuser"] + extra_fields

    fieldsets = [
        (None,             {"fields": (username_field, "password")}),
        (_("Informations personnelles"), {"fields": personal_fields}),
        (_("Permissions"),  {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        (_("Dates"),        {"fields": ("last_login", "date_joined")}),
    ]

    if forge_auth_config.is_enabled_field("status"):
        fieldsets.append(
            (_("Vérification"), {"fields": ("status",)})
        )

    if forge_auth_config.is_enabled_field("otp_secret"):
        fieldsets.append(
            (_("OTP"), {"fields": ("otp_secret",)})
        )

    return fieldsets


def build_list_display():
    base = ["phone_number", "first_name", "last_name", "email", "is_active", "is_staff"]
    if forge_auth_config.is_enabled_field("status"):
        base.append("status")
    return base

"""
forge_auth/admin.py

Enregistrement des modèles forge_auth dans l'administration Django.
Les sections conditionnelles (otp_secret, status) s'adaptent
automatiquement à la configuration forge_auth["OPTIONAL_FIELDS"].
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from forge_auth.conf import forge_auth_config
from forge_auth.models import OtpToken


User = get_user_model()


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


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets         = build_fieldsets()
    list_display      = build_list_display()
    list_filter       = ["is_staff", "is_active"]
    search_fields     = ["phone_number", "first_name", "last_name", "email"]
    ordering          = ["-date_joined"]
    readonly_fields   = ["last_login", "date_joined"]

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("phone_number", "first_name", "last_name", "password1", "password2"),
        }),
    )

_use_otp = forge_auth_config.otp_conf.USE_OTP
_otp_enabled =  "otp_secret" not in forge_auth_config.optional_fields
# Enregistrement conditionnel de OtpToken

if _use_otp and _otp_enabled:
    try:
        @admin.register(OtpToken)
        class OtpTokenAdmin(admin.ModelAdmin):
            list_display  = ["user", "created_at", "updated_at"]
            readonly_fields = ["created_at", "updated_at"]
            search_fields = ["user__phone_number"]
    except Exception:
        pass  # OtpToken est un placeholder — pas de table en base
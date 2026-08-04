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
from forge_auth.models import ApiKey, LoginAuditLog, OtpToken, SessionMetadata, SocialAccount, TotpDevice
from forge_auth.utils import build_fieldsets, build_list_display


User = get_user_model()




@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets         = build_fieldsets()
    list_display      = build_list_display()
    list_filter       = ["is_staff", "is_active"]
    search_fields     = ["phone_number", "first_name", "last_name", "email"]
    ordering          = ["-date_joined"]
    readonly_fields   = ["last_login", "date_joined", 'otp_secret']

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
    # OtpToken est un vrai modèle Django dans cette branche (voir
    # models.py::_use_otp/_otp_enabled) : pas besoin de try/except ici.
    @admin.register(OtpToken)
    class OtpTokenAdmin(admin.ModelAdmin):
        list_display  = ["user", "created_at", "updated_at"]
        readonly_fields = ["created_at", "updated_at"]
        search_fields = ["user__phone_number"]


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ["name", "user", "prefix", "created_at", "last_used_at", "revoked_at"]
    list_filter = ["revoked_at"]
    readonly_fields = ["prefix", "hashed_key", "created_at", "last_used_at"]
    search_fields = ["name", "user__phone_number", "user__email"]


@admin.register(SessionMetadata)
class SessionMetadataAdmin(admin.ModelAdmin):
    list_display = ["user", "ip_address", "user_agent", "created_at", "last_seen_at", "revoked_at"]
    list_filter = ["revoked_at"]
    readonly_fields = ["jti", "created_at", "last_seen_at"]
    search_fields = ["user__phone_number", "user__email", "ip_address"]


@admin.register(LoginAuditLog)
class LoginAuditLogAdmin(admin.ModelAdmin):
    list_display = ["username_attempted", "user", "result", "reason", "ip_address", "created_at"]
    list_filter = ["result"]
    readonly_fields = [f.name for f in LoginAuditLog._meta.fields]
    search_fields = ["username_attempted", "user__phone_number", "user__email", "ip_address"]


@admin.register(TotpDevice)
class TotpDeviceAdmin(admin.ModelAdmin):
    list_display = ["user", "confirmed", "created_at"]
    list_filter = ["confirmed"]
    readonly_fields = ["secret", "created_at"]
    search_fields = ["user__phone_number", "user__email"]


@admin.register(SocialAccount)
class SocialAccountAdmin(admin.ModelAdmin):
    list_display = ["user", "provider", "subject", "email", "created_at"]
    list_filter = ["provider"]
    readonly_fields = ["created_at"]
    search_fields = ["user__phone_number", "user__email", "subject"]
from django.urls import include, path

urlpatterns = [
    path("", include("forge_auth.urls")),
]

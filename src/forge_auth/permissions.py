from rest_framework import permissions


class IsSelfOrAdmin(permissions.BasePermission):
    """
    Empêche l'IDOR sur UserViewSet : sans cette permission, IsAuthenticated
    seul permet à n'importe quel utilisateur connecté de lister, consulter,
    modifier ou supprimer n'importe quel autre utilisateur via /users/{pk}/.

    - `list` : réservé au staff (un utilisateur normal ne doit pas pouvoir
      énumérer tous les comptes).
    - `retrieve` / `update` / `partial_update` / `destroy` : autorisés
      uniquement à l'utilisateur lui-même ou à un membre du staff.
    """

    def has_permission(self, request, view):
        if view.action == "list":
            return bool(request.user and request.user.is_staff)
        return True

    def has_object_permission(self, request, view, obj):
        return bool(request.user and (request.user.is_staff or obj.pk == request.user.pk))

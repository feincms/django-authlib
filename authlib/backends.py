from functools import cache

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend, ModelBackend
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.db.models import ObjectDoesNotExist


class EmailBackend(ModelBackend):
    def _get_user(self, **kwargs):
        try:
            return get_user_model()._default_manager.get(is_active=True, **kwargs)
        except ObjectDoesNotExist:
            return None

    def get_user(self, user_id):
        return self._get_user(pk=user_id)

    def authenticate(self, request, email):
        return self._get_user(email=email)


@cache
def _all_perms():
    queryset = Permission.objects.values_list("content_type__app_label", "codename")
    return [f"{app_label}.{codename}" for app_label, codename in queryset]


class RolePermissionsBackend(BaseBackend):
    """Answers permission checks from the user's role, and nothing else.

    Despite living in ``AUTHENTICATION_BACKENDS`` this backend authenticates
    nobody; it has to be accompanied by one which does.
    """

    def get_user_permissions(self, user, obj=None):
        # ModelBackend can use an optimized variant of this -- we cannot since
        # we don't know what the permission checking callbacks do.
        if obj is not None:
            # Permissions may depend on the object, so never cache those --
            # caching on the user instance would leak results across
            # unrelated objects (and even across obj=None lookups).
            return {perm for perm in _all_perms() if self._has_perm(user, perm, obj)}

        attribute = "_user_permissions_cache"
        if not hasattr(user, attribute):
            perms = {perm for perm in _all_perms() if self._has_perm(user, perm, obj)}
            setattr(user, attribute, perms)
        return getattr(user, attribute)

    def _has_perm(self, user, perm, obj):
        try:
            return self.has_perm(user, perm, obj)
        except PermissionDenied:
            return False

    def get_group_permissions(self, user, obj=None):
        return set()

    def get_all_permissions(self, user, obj=None):
        return self.get_user_permissions(user, obj=obj)

    def has_perm(self, user, perm, obj=None):
        return user._role_has_perm(perm=perm, obj=obj)

    def has_module_perms(self, user_obj, app_label):
        """
        Return True if user_obj has any permissions in the given app_label.
        """
        return user_obj.is_active and any(
            perm[: perm.index(".")] == app_label
            for perm in self.get_all_permissions(user_obj)
        )

    # def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):

    # The user model and its manager will delegate permission lookup functions (get_user_permissions(), get_group_permissions(), get_all_permissions(), has_perm(), has_module_perms(), and with_perm()) to any authentication backend that implements these functions.

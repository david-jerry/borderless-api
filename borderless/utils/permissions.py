from rest_framework.permissions import BasePermission

class IsStaffPermission(BasePermission):
    """
    Custom permission to allow access only to staff members.
    """

    def has_permission(self, request, view):
        return request.user.is_staff

class IsWaitingPermission(BasePermission):
    """Custom permission to allow access only to staff members.
    """

    def has_permission(self, request, view):
        return request.user.waitlisted

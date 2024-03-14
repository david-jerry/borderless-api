from django.conf import settings
from django.urls import path

from rest_framework.routers import DefaultRouter, SimpleRouter

from borderless.users.api.views import (
    CheckUserViewSet,
    LogoutViewset,
    PasswordChangeViewset,
    PasswordResetConfirmViewset,
    PasswordResetViewset,
    UserLoginViewset,
    RegisterViewset,
    ResendEmailVerificationViewset,
    VerifyEmailViewset,
    TokenRefreshViewset,
    UserViewSet,
    ActivityViewSet,
    SubscribersViewSet,
    email_confirm_redirect,
    password_reset_confirm_redirect,
)

if settings.DEBUG:
    router = DefaultRouter()
else:
    router = SimpleRouter()

router.register("auth/login", UserLoginViewset, basename="login")
router.register("auth/token-refresh", TokenRefreshViewset, basename="token_refresh")
router.register("auth/register", RegisterViewset, basename="register")
router.register("auth/resend-email-verification", ResendEmailVerificationViewset, basename="resend_email_verification")
router.register("auth/password/change-password", PasswordChangeViewset, basename="account_password_change")
router.register("auth/password/reset", PasswordResetViewset, basename="account_password_reset")
router.register("auth/password/reset/confirm", PasswordResetConfirmViewset, basename="password_reset_confirm")
router.register("validate", CheckUserViewSet)
router.register("activities", ActivityViewSet, basename="activity")
router.register("waiters", SubscribersViewSet, basename="waiter")
router.register("users", UserViewSet, basename="user")


app_name = "api"
urlpatterns = router.urls

urlpatterns += [
    path("auth/logout/", LogoutViewset.as_view(), name="account_logout"),
    path("auth/email/verify-email/", VerifyEmailViewset.as_view(), name="account_verify_email"),
    path("auth/email/confirm-email/<str:key>/", email_confirm_redirect, name="account_confirm_email"),
    path(
        "auth/password/reset/confirm/<str:uidb64>/<str:token>/",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    # path("auth/password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]

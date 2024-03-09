from django.conf import settings
from django.urls import path

from rest_framework.routers import DefaultRouter, SimpleRouter

from borderless.users.api.views import (
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
router.register("auth/registration/resend-email-verification", ResendEmailVerificationViewset, basename="resend_email_verification")
router.register("auth/password/change", PasswordChangeViewset, basename="account_password_change")
router.register("auth/password/reset", PasswordResetViewset, basename="account_password_reset")
router.register("auth/password/reset/confirm", PasswordResetConfirmViewset, basename="password_reset_confirm")
router.register("users", UserViewSet, basename="user")


app_name = "api"
urlpatterns = router.urls

urlpatterns += [
    path("auth/logout/", LogoutViewset.as_view(), name="account_logout"),
    path("auth/registration/verify-email/", VerifyEmailViewset.as_view(), name="account_verify_email"),
    path("auth/registration/account-confirm-email/<str:key>/", email_confirm_redirect, name="account_confirm_email"),
    path(
        "auth/password/reset/confirm/<str:uidb64>/<str:token>/",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    # path("auth/password/reset/confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]

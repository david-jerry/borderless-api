
from typing import ClassVar

from django.contrib.auth.models import AbstractUser
from django.db.models import CharField, EmailField, BooleanField
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from borderless.users.managers import UserManager


class User(AbstractUser):
    """
    Default custom user model for borderless.
    If adding fields that need to be filled at user signup,
    check forms.SignupForm and forms.SocialSignupForms accordingly.
    """

    # First and last name do not cover name patterns around the globe
    username = None  # type: ignore
    first_name = None  # type: ignore
    last_name = None  # type: ignore

    name = CharField(_("Name of User"), blank=True, max_length=255)
    phone = CharField(_("Mobile Number"), blank=True, max_length=14)
    country = CharField(_("Country of Residency"), blank=True, max_length=120)
    email = EmailField(_("Email Address"), unique=True)
    waitlisted = BooleanField(_('Waitlisted'), default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects: ClassVar[UserManager] = UserManager()

    class Meta:
        managed = True
        verbose_name = "User Account"
        verbose_name_plural = "Users Account"

    def get_absolute_url(self) -> str:
        """Get URL for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"pk": self.id})

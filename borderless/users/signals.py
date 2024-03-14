from allauth.account.signals import user_signed_up, user_logged_in
from allauth.account.adapter import get_adapter

from django.contrib.auth.signals import user_logged_in as admin_logged_in

from .models import Activities, User
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch import receiver


@receiver(post_save, sender=User)
def update_cached_users(sender, instance, created, **kwargs):
    if created:
        user_dict = {
            "id": instance.id,
            "email": instance.email,
            "phone": instance.phone,
            "country": instance.country,
            "name": instance.name,
            "is_staff": instance.is_staff,
            "date_joined": instance.date_joined,
            "waitlisted": instance.waitlisted,
        }

        if not instance.is_staff:
            Activities.objects.create(identity=instance.name, activity_type=Activities.SIGNUP)
        cached_users = cache.get("user_emails", [])
        cached_users.append(user_dict)
        cache.set("user_emails", cached_users)


@receiver(user_logged_in)
def perform_actions_on_login(sender, request, user, **kwargs):
    adapter = get_adapter(request)
    user_ip = adapter.get_client_ip(request)
    if request.user.is_staff:
        Activities.objects.create(identity=user_ip, activity_type=Activities.LOGIN)


@receiver(admin_logged_in)
def admin_actions_on_login(sender, request, user, **kwargs):
    adapter = get_adapter(request)
    user_ip = adapter.get_client_ip(request)
    if request.user.is_staff:
        Activities.objects.create(identity=user_ip, activity_type=Activities.LOGIN)

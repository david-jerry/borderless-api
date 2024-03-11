from .models import User
from django.core.cache import cache
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def update_cached_users(sender, instance, created, **kwargs):
    if created:
        user_dict = {
            "id": instance.id,
            'email': instance.email,
            'phone': instance.phone,
            "country": instance.country,
            'name': instance.name,
            'is_staff': instance.is_staff,
            'date_joined': instance.date_joined,
            "waitlisted": instance.waitlisted,
        }
        cached_users = cache.get('user_emails', [])
        cached_users.append(user_dict)
        cache.set('user_emails', cached_users)
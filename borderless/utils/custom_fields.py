from django.db import models

class ListField(models.TextField):
    """
    Stores a list of strings.

    and can be appended with more information using this method:
    foo.field += f"{bar}, "
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        if not value:
            return []
        return [item.strip() for item in value.split(',')]

    def get_prep_value(self, value):
        if not value:
            return ''
        return value

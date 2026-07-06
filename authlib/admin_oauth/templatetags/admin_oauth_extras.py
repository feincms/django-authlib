from django import template
from django.conf import settings


register = template.Library()


@register.simple_tag
def get_setting(name, default=None):
    """Get a setting value and optionally assign it to a variable."""
    return getattr(settings, name, default)

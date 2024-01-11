"""
ASGI config for insyncbackend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os
import django
from .channelsmiddleware import JwtAuthMiddleware
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application
from chat.routing import websocket_urlpatterns as chat_websocket_urlpatterns
from post.routing import websocket_urlpatterns as post_websocket_urlpatterns


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'insyncbackend.settings')
django.setup()

django_asgi_application = get_asgi_application()

application = ProtocolTypeRouter(
    {
        'http': django_asgi_application,
        'websocket': JwtAuthMiddleware(
            AllowedHostsOriginValidator(URLRouter(chat_websocket_urlpatterns + post_websocket_urlpatterns))
        )
    
    }
)

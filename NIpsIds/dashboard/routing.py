from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'^ws/snort_console_output/$', consumers.SnortConsoleConsumer.as_asgi()),
]
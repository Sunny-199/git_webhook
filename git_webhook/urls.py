
from git_webhook.views import GitWebhook
from django.urls import path

urlpatterns = [
    path('webhook/', GitWebhook.as_view(), name='webhook'),
]
from . import views
from django.urls import path

urlpatterns = [
    path('webhook/', views.hello, name='webhook'),
]
from django.urls import path
from . import views

app_name = 'hasher'

urlpatterns = [
    path('', views.index, name='index'),
]
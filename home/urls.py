from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_page, name='home_page'),
    path('test_blocker/', views.test_endpoint, name='blocker'),
    path('time/', views.get_time, name='get_time'),
]
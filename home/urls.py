from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_page, name='home_page'),
    path('test_blocker/', views.test_endpoint, name='blocker'),
    path('test_blocker_temporary/', views.test_endpoint_2, name='temp_blocker'),
    path('time/', views.get_time, name='get_time'),
]
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_page, name='home_page'),
    path('blocker/', views.test_endpoint, name='blocker'),
    path('temporary_blocker/', views.test_endpoint_2, name='temp_blocker'),
    path('get_stats/', views.get_blocker_stats_view, name='get_stats'),
    path('block_ip/', views.block_ip_view, name='block_ip'),
    path('unblock_ip/', views.unblock_ip_view, name='unblock_ip'),
    # path('time/', views.get_time, name='get_time'),
]
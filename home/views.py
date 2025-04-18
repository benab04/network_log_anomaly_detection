from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime
import json

from django_attack_blocker import MLIPBlocker,with_ip_blocking, unblock_ip, block_ip, get_blocker_stats

# We create an instance of the MLIPBlocker class
# The model_path, encoder_path should be in the root directory of the project, where manage.py is located.
blocker = MLIPBlocker(
    model_path='model.joblib',
    encoder_path='encoder.pkl',
    block_threshold=0.5,
    block_timeout=10,
)

# This view is for the home page of the Django application.
def home_page(request):
    return JsonResponse({"message": "Welcome to the home page!"})

# This view is for the permanent blocking of IP addresses.
@with_ip_blocking(blocker, type="permanent")
def test_endpoint(request):
    return JsonResponse({"message": "Welcome to the django attack blocker testing page!"})


# This view is for the temporary blocking of IP addresses.
# The block_timeout is set to 10 seconds, which means that the IP address will be blocked for 10 seconds.
@with_ip_blocking(blocker)
def test_endpoint_2(request):
    return JsonResponse({"message": "Welcome to the temporary django attack blocker testing page!"})

# This view is for unblocking a specific IP address.
def unblock_ip_view(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        unblock_ip(blocker, ip)
        return JsonResponse({"message": f"IP unblocked successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
    
# This view is for blocking a specific IP address, either temporarily or permanently.
# The duration is in seconds, and if not provided, it will block the IP permanently.    
def block_ip_view(request):
    try:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        
        try:
            request_body = json.loads(request.body.decode('utf-8'))
            duration = request_body.get('duration', None)
        except Exception as e:
            print(e)
        
        
        block_ip(blocker, ip, duration)
        return JsonResponse({"message": f"IP blocked successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
# This view is for getting the stats of the IP blocker
def get_blocker_stats_view(request):
    try:
        stats = get_blocker_stats(blocker=blocker)
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

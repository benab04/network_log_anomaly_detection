from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime
import json

# from home.utils import process, _load_model, json_to_dataframe
# from .core import MLIPBlocker, with_ip_blocking

from django_attack_blocker import MLIPBlocker,with_ip_blocking, unblock_ip, block_ip, get_blocker_stats

blocker = MLIPBlocker(
    model_path='model.joblib',
    encoder_path='encoder.pkl',
    # blocklist_path='blocklist.txt',
    block_threshold=0.5,
    block_timeout=10,

    # trusted_ips=['192.168.1.1', '10.0.0.0/8'],  # IPs that are always allowed
    # blocked_ips=['1.2.3.4', '5.6.7.0/24']  # IPs that are always blocked
)

# blocker2 = MLIPBlocker(
#     model_path='model.joblib',
#     encoder_path='encoder.pkl',
#     # blocklist_path='blocklist.txt',
#     block_threshold=0.5,
#     block_timeout=10,
#     # trusted_ips=['192.168.1.1', '10.0.0.0/8'],  # IPs that are always allowed
#     # blocked_ips=['1.2.3.4', '5.6.7.0/24']  # IPs that are always blocked
# )


def home_page(request):
    return JsonResponse({"message": "Welcome to the home page!"})

@with_ip_blocking(blocker, type="permanent")
def test_endpoint(request):
    return JsonResponse({"message": "Welcome to the django attack blocker testing page!"})


@with_ip_blocking(blocker)
def test_endpoint_2(request):
    return JsonResponse({"message": "Welcome to the temporary django attack blocker testing page!"})


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
    
def get_blocker_stats_view(request):
    try:
        stats = get_blocker_stats(blocker=blocker)
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

# @with_ip_blocking(blocker)
# def get_time (request):
    
#     if request.method != 'POST':
#         return JsonResponse({"error": "Method not allowed"}, status=405)
    
#     now = datetime.now()
#     current_time = now.strftime("%H:%M:%S")

#     # mediator = create_mediator('rf_model.pkl', 'blocklist.txt')
#     ## Process through mediator
#     # response, status_code = handle_api_request(request_info, mediator)
    
#     # print(response, status_code)
#     model =_load_model('rf_model_2.pkl')
    
#     try:
#         request_body = request.body.decode('utf-8')
        
#         df= json_to_dataframe(json.loads(request_body)) 
        
#         X = process(df)
        
#         y = model.predict(X)
        
#         print("Output: ", y)
        
#     except Exception as e:
#         print("Error decoding request body:", str(e))
        
        
#     return JsonResponse({"time": current_time})
    
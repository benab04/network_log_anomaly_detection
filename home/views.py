from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime
import json

# from home.utils import process, _load_model, json_to_dataframe
# from .core import MLIPBlocker, with_ip_blocking

from django_attack_blocker import MLIPBlocker,with_ip_blocking

blocker = MLIPBlocker(
    model_path='model.joblib',
    encoder_path='encoder.pkl',
    # blocklist_path='blocklist.txt',
    block_threshold=0.5,
    # trusted_ips=['192.168.1.1', '10.0.0.0/8'],  # IPs that are always allowed
    # blocked_ips=['1.2.3.4', '5.6.7.0/24']  # IPs that are always blocked
)

blocker2 = MLIPBlocker(
    model_path='model.joblib',
    encoder_path='encoder.pkl',
    # blocklist_path='blocklist.txt',
    block_threshold=0.5,
    block_timeout=10,
    # trusted_ips=['192.168.1.1', '10.0.0.0/8'],  # IPs that are always allowed
    # blocked_ips=['1.2.3.4', '5.6.7.0/24']  # IPs that are always blocked
)


def home_page(request):
    return JsonResponse({"message": "Welcome to the home page!"})

@with_ip_blocking(blocker)
def test_endpoint(request):
    return JsonResponse({"message": "Welcome to the django attack blocker testing page!"})


@with_ip_blocking(blocker2)
def test_endpoint_2(request):
    return JsonResponse({"message": "Welcome to the temporary django attack blocker testing page!"})

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
    
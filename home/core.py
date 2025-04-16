# django_ml_ipblocker/core.py

import pickle
from joblib import load
import pandas as pd
import numpy as np
import json
import logging
from datetime import datetime, timedelta
from django.http import JsonResponse
from django.core.cache import cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from .utils import process, json_to_dataframe

logger = logging.getLogger(__name__)

class MLIPBlocker:
    """
    A class for blocking/allowing IP addresses based on ML model predictions.
    """
    
    def __init__(self, model_path=None, blocklist_path=None, 
                 block_threshold=0.5, cache_timeout=10,
                 trusted_ips=None, blocked_ips=None):
        """
        Initialize the IP Blocker with settings.
        
        Parameters:
        - model_path: Path to pickled ML model file
        - blocklist_path: Path to a file with IPs to always block
        - block_threshold: Threshold above which to block (for models that return probabilities)
        - cache_timeout: How long to keep IP block decisions cached (in seconds)
        - trusted_ips: List of IP addresses or CIDR ranges to always allow
        - blocked_ips: List of IP addresses or CIDR ranges to always block
        """
        self.model = self._load_model(model_path) if model_path else None
        self.block_threshold = block_threshold
        self.cache_timeout = cache_timeout
        
        # Load permanent blocklist if provided
        self.blocklist = set()
        if blocklist_path:
            try:
                with open(blocklist_path, 'r') as f:
                    self.blocklist = set(line.strip() for line in f if line.strip())
            except Exception as e:
                logger.error(f"Error loading blocklist: {str(e)}")
        
        # Pre-configured IPs
        self.trusted_ips = []
        if trusted_ips:
            for ip in trusted_ips:
                try:
                    if '/' in ip:
                        self.trusted_ips.append(ip_network(ip))
                    else:
                        self.trusted_ips.append(ip_address(ip))
                except ValueError:
                    logger.warning(f"Invalid trusted IP format: {ip}")
        
        self.blocked_ips = []
        if blocked_ips:
            for ip in blocked_ips:
                try:
                    if '/' in ip:
                        self.blocked_ips.append(ip_network(ip))
                    else:
                        self.blocked_ips.append(ip_address(ip))
                except ValueError:
                    logger.warning(f"Invalid blocked IP format: {ip}")
        
        # Stats
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'model_failures': 0,
            'cache_hits': 0,
        }
    
    def _load_model(self, model_path):
        """Load ML model from pickle file"""
        try:
            with open(model_path, 'rb') as f:
                return load(f)
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return None
    
    def _check_trusted_ips(self, ip):
        """Check if IP is in trusted IPs list"""
        try:
            client_ip = ip_address(ip)
            
            # Check if IP is in trusted networks
            for trusted in self.trusted_ips:
                # Check if trusted is a network
                if isinstance(trusted, (IPv4Network, IPv6Network)) and client_ip in trusted:
                    return True
                # Check if trusted is an IP address
                elif isinstance(trusted, (IPv4Address, IPv6Address)) and trusted == client_ip:
                    return True
            
            return False
        except ValueError:
            logger.warning(f"Invalid IP format: {ip}")
            return False
    
    def _check_blocked_ips(self, ip):
        """Check if IP is in blocked IPs list"""
        try:
            if ip in self.blocklist:
                return True
                
            client_ip = ip_address(ip)
            
            # Check if IP is in blocked networks
            for blocked in self.blocked_ips:
                # Check if blocked is a network
                if isinstance(blocked, (IPv4Network, IPv6Network)) and client_ip in blocked:
                    return True
                # Check if blocked is an IP address
                elif isinstance(blocked, (IPv4Address, IPv6Address)) and blocked == client_ip:
                    return True
            
            return False
        except ValueError:
            logger.warning(f"Invalid IP format: {ip}")
            return False
    
    # def json_to_dataframe(self, json_data):
    #     """Convert JSON to pandas DataFrame"""
    #     if isinstance(json_data, dict):
    #         return pd.DataFrame([json_data])
    #     elif isinstance(json_data, list):
    #         return pd.DataFrame(json_data)
    #     else:
    #         raise ValueError("Input must be a dict or list")
    
   
    
    def should_block(self, request, extra_data=None):
        """
        Determine if request should be blocked based on IP and other data.
        
        Parameters:
        - request: Django request object
        - extra_data: Additional data to use for model prediction
        
        Returns:
        - (bool): True if request should be blocked, False otherwise
        """
        self.stats['total_requests'] += 1
        
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Always allow trusted IPs
        if self._check_trusted_ips(ip):
            self.stats['allowed_requests'] += 1
            return False
        
        # Always block IPs in blocklist
        if self._check_blocked_ips(ip):
            self.stats['blocked_requests'] += 1
            return True
        
        # Check cache for previous decisions
        cache_key = f"ipblocker:decision:{ip}"
        cached_decision = cache.get(cache_key)
        if cached_decision is not None:
            self.stats['cache_hits'] += 1
            if cached_decision:
                self.stats['blocked_requests'] += 1
            else:
                self.stats['allowed_requests'] += 1
            return cached_decision
        
        # No model means we can't make ML-based decisions
        if self.model is None:
            self.stats['allowed_requests'] += 1
            return False
        
        # Build features for model
        try:
            # request_data = {
            #     'ip': ip,
            #     'path': request.path,
            #     'method': request.method,
            #     'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            #     'timestamp': datetime.now().isoformat(),
            # }
            
            # Add request body if it exists and is JSON
            try:
                if request.body:
                    body = json.loads(request.body.decode('utf-8'))
                    # request_data['body'] = body
            except:
                # Not JSON or empty body, that's fine
                pass
                
            # Add headers (excluding sensitive ones)
            # headers = {}
            # for key, value in request.META.items():
            #     if key.startswith('HTTP_') and key not in ('HTTP_COOKIE', 'HTTP_AUTHORIZATION'):
            #         headers[key] = value
            # request_data['headers'] = headers
            
            # Add extra data if provided
            # if extra_data:
            #     request_data.update(extra_data)
                
            # Prepare data for model
            df = json_to_dataframe(body)
            X = process(df)
            
            # Get model prediction
            prediction = self.model.predict(X)
            # Print the attributes of the model
            # Handle different model outputs
            if hasattr(self.model, 'predict_proba'):
                # For probabilistic models, get probability and compare to threshold
                proba = self.model.predict_proba(X)
                
                if proba.shape[1] == 2:  # Binary classification
                    block_probability = proba[0, 1]  # Probability of class 1 (block)
                    block_decision = block_probability >= self.block_threshold
                    print(f"Block decision: {block_decision}, Probability: {block_probability:.4f}, Threshold: {self.block_threshold}")
                else:
                    # Get the predicted class
                    block_decision = bool(prediction[0])
                    print(f"Block decision: {block_decision}, Predicted class: {prediction[0]}")
            else:
                # For non-probabilistic models, use the prediction directly
                block_decision = bool(prediction[0])
                print(f"Block decision: {block_decision}, Prediction: {prediction[0]}")

            # Cache the decision
            if block_decision:
                self.block_ip(ip)
            cache.set(cache_key, block_decision, self.cache_timeout)
            
            # Update stats
            if block_decision:
                self.stats['blocked_requests'] += 1
            else:
                self.stats['allowed_requests'] += 1
                
            return block_decision
            
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            self.stats['model_failures'] += 1
            self.stats['allowed_requests'] += 1
            return False
    
    def get_stats(self):
        """Return statistics on IP blocking"""
        return self.stats
    
    def block_ip(self, ip, duration=None):
        """
        Manually block an IP address
        
        Parameters:
        - ip: IP address to block
        - duration: Duration to block for (in seconds), or None for permanent
        """
        if duration:
            # Temporary block using cache
            cache_key = f"ipblocker:decision:{ip}"
            cache.set(cache_key, True, duration)
        else:
            # Permanent block by adding to blocklist
            self.blocklist.add(ip)
    
    def unblock_ip(self, ip):
        """
        Unblock an IP address
        
        Parameters:
        - ip: IP address to unblock
        """
        # Remove from blocklist if present
        if ip in self.blocklist:
            self.blocklist.remove(ip)
        
        # Clear from cache
        cache_key = f"ipblocker:decision:{ip}"
        cache.delete(cache_key)


# Helper functions to use the blocker in views
def block_if_malicious(blocker, view_func):
    """
    Decorator for Django views to block malicious requests
    """
    def wrapped_view(request, *args, **kwargs):
        if blocker.should_block(request):
            return JsonResponse({
                "error": "Access denied",
                "message": "Your request has been blocked"
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapped_view


def with_ip_blocking(blocker):
    """
    Decorator factory to use with Django views
    
    Example:
    @with_ip_blocking(my_blocker)
    def my_view(request):
        # View code here
    """
    def decorator(view_func):
        def wrapped_view(request, *args, **kwargs):
            if blocker.should_block(request):
                return JsonResponse({
                    "error": "Access denied",
                    "message": "Your request has been blocked"
                }, status=403)
            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator
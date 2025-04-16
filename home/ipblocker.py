# django_attack_blocker/middleware.py
import pickle
import json
import logging
import ipaddress
from datetime import datetime, timedelta
from threading import Lock
from django.http import JsonResponse
from django.conf import settings

logger = logging.getLogger(__name__)

class IPBlocker:
    """Class to maintain and check blocked IP addresses with optional expiration"""
    
    def __init__(self, default_block_duration=None):
        """
        Initialize the IP blocker.
        
        Args:
            default_block_duration: Default time in minutes to block IPs (None for permanent)
        """
        self.blocked_ips = {}  # Maps IP to expiration time (None for permanent)
        self.lock = Lock()
        self.default_block_duration = default_block_duration
    
    def add_ip(self, ip, duration=None):
        """
        Add an IP to the blocklist
        
        Args:
            ip: IP address to block
            duration: Time in minutes to block (None uses default, -1 for permanent)
        """
        with self.lock:
            expiry = None
            if duration == -1:
                expiry = None  # Permanent block
            elif duration is not None:
                expiry = datetime.now() + timedelta(minutes=duration)
            elif self.default_block_duration is not None:
                expiry = datetime.now() + timedelta(minutes=self.default_block_duration)
            
            self.blocked_ips[ip] = expiry
            logger.warning(f"IP {ip} blocked until {expiry if expiry else 'permanently'}")
    
    def is_blocked(self, ip):
        """Check if an IP is blocked, cleanup expired blocks"""
        with self.lock:
            if ip in self.blocked_ips:
                expiry = self.blocked_ips[ip]
                if expiry is None:
                    return True  # Permanent block
                elif expiry > datetime.now():
                    return True  # Block still active
                else:
                    # Block expired, remove it
                    del self.blocked_ips[ip]
                    logger.info(f"Block for IP {ip} expired and removed")
            return False
    
    def remove_ip(self, ip):
        """Remove an IP from the blocklist"""
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                logger.info(f"IP {ip} removed from blocklist")
    
    def cleanup_expired(self):
        """Remove all expired IP blocks"""
        now = datetime.now()
        with self.lock:
            expired = [ip for ip, expiry in self.blocked_ips.items() 
                      if expiry is not None and expiry <= now]
            for ip in expired:
                del self.blocked_ips[ip]
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired IP blocks")
    
    def get_blocked_ips(self):
        """Return a list of currently blocked IPs with their expiry times"""
        with self.lock:
            self.cleanup_expired()
            return {ip: str(expiry) if expiry else "permanent" 
                   for ip, expiry in self.blocked_ips.items()}


class RequestFeatureExtractor:
    """Extract features from Django request objects for ML model input"""
    
    @staticmethod
    def json_to_dataframe(json_data):
        """Convert JSON data to a format compatible with your model"""
        # This is a placeholder - replace with your actual implementation
        # that matches the structure expected by your model
        import pandas as pd
        return pd.DataFrame([json_data])
    
    @staticmethod
    def extract_features(request):
        """Extract relevant features from a Django request"""
        # Extract information from the request
        ip = RequestFeatureExtractor.get_client_ip(request)
        method = request.method
        path = request.path
        
        # Create a features dictionary
        features = {
            'ip': ip,
            'method': method,
            'path': path,
            'content_length': len(request.body) if request.body else 0,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'content_type': request.META.get('CONTENT_TYPE', ''),
            'query_params': len(request.GET),
            'timestamp': datetime.now().timestamp(),
        }
        
        # Include POST data if present
        if method == 'POST' and request.body:
            try:
                body = request.body.decode('utf-8')
                if body:
                    try:
                        # Try to parse as JSON
                        json_body = json.loads(body)
                        features['body_length'] = len(body)
                        features['json_fields'] = len(json_body) if isinstance(json_body, dict) else 0
                    except json.JSONDecodeError:
                        # Not JSON, just use the length
                        features['body_length'] = len(body)
                        features['json_fields'] = 0
            except UnicodeDecodeError:
                # Binary data
                features['body_length'] = len(request.body)
                features['json_fields'] = 0
        
        return features
    
    @staticmethod
    def get_client_ip(request):
        """Get the client IP address from the request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def process(features_df):
        """Process the features into the format expected by your model"""
        # This should implement your feature processing logic
        # that matches what you've done in your `process()` function
        return features_df


class AttackBlockerMiddleware:
    """Django middleware to block malicious requests using ML prediction"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.blocker = self._initialize_blocker()
        self.model = self._load_model()
        
        # Load settings
        self.enabled = getattr(settings, 'ATTACK_BLOCKER_ENABLED', True)
        self.block_threshold = getattr(settings, 'ATTACK_BLOCKER_THRESHOLD', 0.8)
        self.block_duration = getattr(settings, 'ATTACK_BLOCKER_DURATION', 60)  # minutes
        self.whitelisted_ips = set(getattr(settings, 'ATTACK_BLOCKER_WHITELIST', []))
        self.exempt_paths = set(getattr(settings, 'ATTACK_BLOCKER_EXEMPT_PATHS', ['/admin', '/static']))
        
        logger.info(f"Attack Blocker Middleware initialized (enabled={self.enabled})")
    
    def _initialize_blocker(self):
        """Initialize the IP blocker with settings"""
        default_duration = getattr(settings, 'ATTACK_BLOCKER_DURATION', 60)  # Default 60 minutes
        return IPBlocker(default_block_duration=default_duration)
    
    def _load_model(self):
        """Load the ML model for attack detection"""
        model_path = getattr(settings, 'ATTACK_BLOCKER_MODEL_PATH', 'rf_model_2.pkl')
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
                logger.info(f"Loaded attack detection model from {model_path}")
                return model
        except Exception as e:
            logger.error(f"Failed to load attack detection model: {str(e)}")
            return None
    
    def _is_path_exempt(self, path):
        """Check if the path is exempt from blocking"""
        return any(path.startswith(exempt) for exempt in self.exempt_paths)
    
    def _is_ip_whitelisted(self, ip):
        """Check if the IP is in the whitelist"""
        # Check direct match
        if ip in self.whitelisted_ips:
            return True
        
        # Check CIDR notation whitelist items
        try:
            ip_obj = ipaddress.ip_address(ip)
            for item in self.whitelisted_ips:
                if '/' in item:  # CIDR notation
                    try:
                        network = ipaddress.ip_network(item, strict=False)
                        if ip_obj in network:
                            return True
                    except ValueError:
                        continue
        except ValueError:
            pass
        
        return False
    
    def __call__(self, request):
        """Process the request and block if classified as malicious"""
        if not self.enabled:
            return self.get_response(request)
        
        client_ip = RequestFeatureExtractor.get_client_ip(request)
        
        # Check if path is exempt
        if self._is_path_exempt(request.path):
            return self.get_response(request)
        
        # Check if IP is whitelisted
        if self._is_ip_whitelisted(client_ip):
            return self.get_response(request)
        
        # Check if IP is already blocked
        if self.blocker.is_blocked(client_ip):
            logger.warning(f"Blocked request from blocked IP: {client_ip}")
            return JsonResponse({
                "error": "Your IP address has been blocked due to suspicious activity",
                "status": "blocked"
            }, status=403)
        
        # Process the request with the ML model
        if self.model is not None:
            try:
                # Extract features from request
                features = RequestFeatureExtractor.extract_features(request)
                
                # Convert to dataframe and process
                df = RequestFeatureExtractor.json_to_dataframe(features)
                X = RequestFeatureExtractor.process(df)
                
                # Make prediction
                prediction = self.model.predict(X)
                
                # Get probabilities if available
                pred_proba = None
                if hasattr(self.model, 'predict_proba'):
                    pred_proba = self.model.predict_proba(X)
                    malicious_prob = max(pred_proba[0]) if pred_proba is not None else None
                else:
                    malicious_prob = 1.0 if prediction[0] == 1 else 0.0
                
                logger.debug(f"Request from {client_ip} classified as {prediction[0]} (prob: {malicious_prob})")
                print(f"Request from {client_ip}  (prob: {malicious_prob})")
                # Block IP if classified as attack with high probability
                if prediction[0] == 1 or (malicious_prob is not None and malicious_prob >= self.block_threshold):
                    logger.warning(f"Blocking IP {client_ip} - classified as attack with probability {malicious_prob}")
                    self.blocker.add_ip(client_ip, duration=self.block_duration)
                    return JsonResponse({
                        "error": "Your IP address has been blocked due to suspicious activity",
                        "status": "blocked"
                    }, status=403)
                
            except Exception as e:
                logger.error(f"Error predicting attack: {str(e)}")
        
        # Continue with the normal request if not blocked
        return self.get_response(request)


# Admin interface for managing blocked IPs
class BlockerAdminView:
    """Admin interface for managing blocked IPs (can be integrated with Django admin)"""
    
    @staticmethod
    def get_blocked_ips(blocker):
        """Get the list of blocked IPs"""
        return blocker.get_blocked_ips()
    
    @staticmethod
    def unblock_ip(blocker, ip):
        """Unblock an IP address"""
        blocker.remove_ip(ip)
        return True
    
    @staticmethod
    def block_ip(blocker, ip, duration=None):
        """Block an IP address"""
        blocker.add_ip(ip, duration=duration)
        return True


# django_attack_blocker/apps.py
from django.apps import AppConfig

class DjangoAttackBlockerConfig(AppConfig):
    name = 'django_attack_blocker'
    verbose_name = 'Django Attack Blocker'
    
    def ready(self):
        # Perform startup actions like loading models
        pass


# django_attack_blocker/utils.py 
def load_model(model_path):
    """Load a machine learning model from a pickle file"""
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        raise ValueError(f"Failed to load model from {model_path}: {str(e)}")
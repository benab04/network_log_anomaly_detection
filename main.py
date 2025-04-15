import pickle
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import ipaddress

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='anomaly_detection.log'
)
logger = logging.getLogger('anomaly_detector')

class AnomalyDetectionMediator:
    def __init__(self, model_path, blocklist_path):
        """
        Initialize the mediator with paths to the model and blocklist
        
        Args:
            model_path (str): Path to the trained anomaly detection model (.pkl file)
            blocklist_path (str): Path to store the blocklist
        """
        self.model_path = model_path
        self.blocklist_path = blocklist_path
        self.model = self._load_model()
        self.blocklist = self._load_blocklist()
        
    def _load_model(self):
        """Load the trained anomaly detection model"""
        try:
            with open(self.model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"Successfully loaded model from {self.model_path}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def _load_blocklist(self):
        """Load the IP blocklist or create new if not exists"""
        try:
            blocklist = set()
            try:
                with open(self.blocklist_path, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip:
                            blocklist.add(ip)
            except FileNotFoundError:
                # Create new blocklist file if it doesn't exist
                with open(self.blocklist_path, 'w') as f:
                    pass
            logger.info(f"Loaded blocklist with {len(blocklist)} IPs")
            return blocklist
        except Exception as e:
            logger.error(f"Error loading blocklist: {e}")
            return set()
    
    def _save_blocklist(self):
        """Save the current blocklist to file"""
        try:
            with open(self.blocklist_path, 'w') as f:
                for ip in self.blocklist:
                    f.write(f"{ip}\n")
            logger.info(f"Saved blocklist with {len(self.blocklist)} IPs")
        except Exception as e:
            logger.error(f"Error saving blocklist: {e}")
    
    def _extract_features(self, request_data, log_data):
        """
        Transform log data into UNSW dataset feature format
        
        Args:
            request_data (dict): Information about the request
            log_data (dict): Log data to transform
            
        Returns:
            pandas.DataFrame: Features in UNSW dataset format
        """
        # Create a dictionary to hold the features
        features = {}
        
        # Basic flow features
        features['dur'] = log_data.get('dur', 0)
        features['proto'] = log_data.get('proto', self._encode_protocol('unknown'))
        features['service'] = log_data.get('service', self._encode_service('unknown'))
        features['state'] = log_data.get('state', self._encode_state('unknown'))
        
        # Source/destination info
        src_ip = log_data.get('src_ip', request_data.get('ip', '0.0.0.0'))
        dst_ip = log_data.get('dst_ip', '0.0.0.0')
        features['spkts'] = log_data.get('spkts', 1)
        features['dpkts'] = log_data.get('dpkts', 0)
        features['sbytes'] = log_data.get('sbytes', request_data.get('content_length', 0))
        features['dbytes'] = log_data.get('dbytes', 0)
        
        # Time-based features
        features['rate'] = log_data.get('rate', 0)
        features['sttl'] = log_data.get('sttl', 64)
        features['dttl'] = log_data.get('dttl', 64)
        features['sload'] = log_data.get('sload', 0)
        features['dload'] = log_data.get('dload', 0)
        
        # Connection features
        features['sinpkt'] = log_data.get('sinpkt', 0)
        features['dinpkt'] = log_data.get('dinpkt', 0)
        features['sjit'] = log_data.get('sjit', 0)
        features['djit'] = log_data.get('djit', 0)
        
        # TCP connection features
        features['swin'] = log_data.get('swin', 0)
        features['dwin'] = log_data.get('dwin', 0)
        features['stcpb'] = log_data.get('stcpb', 0)
        features['dtcpb'] = log_data.get('dtcpb', 0)
        
        # Additional features from UNSW dataset
        features['tcprtt'] = log_data.get('tcprtt', 0)
        features['synack'] = log_data.get('synack', 0)
        features['ackdat'] = log_data.get('ackdat', 0)
        
        # HTTP specific features if available
        features['ct_srv_src'] = log_data.get('ct_srv_src', 1)
        features['ct_srv_dst'] = log_data.get('ct_srv_dst', 1)
        features['ct_dst_ltm'] = log_data.get('ct_dst_ltm', 1)
        features['ct_src_ltm'] = log_data.get('ct_src_ltm', 1)
        features['ct_src_dport_ltm'] = log_data.get('ct_src_dport_ltm', 1)
        features['ct_dst_sport_ltm'] = log_data.get('ct_dst_sport_ltm', 1)
        features['ct_dst_src_ltm'] = log_data.get('ct_dst_src_ltm', 1)
        
        # Create IP-based features
        features['is_private_src'] = int(self._is_private_ip(src_ip))
        features['is_private_dst'] = int(self._is_private_ip(dst_ip))
        
        # Additional request-specific features
        features['request_method'] = self._encode_http_method(request_data.get('method', 'GET'))
        features['request_path_length'] = len(request_data.get('path', ''))
        features['request_query_params'] = len(request_data.get('query_params', {}))
        features['request_header_count'] = len(request_data.get('headers', {}))
        
        # Create DataFrame with features
        df = pd.DataFrame([features])
        
        # Handle categorical features (convert to one-hot encoding if needed)
        # This depends on how your model was trained
        
        return df
    
    def _encode_protocol(self, protocol):
        """Encode protocol to match UNSW dataset encoding"""
        protocol_map = {
            'tcp': 0, 'udp': 1, 'icmp': 2, 'arp': 3, 'unknown': 4
        }
        return protocol_map.get(protocol.lower(), 4)
    
    def _encode_service(self, service):
        """Encode service to match UNSW dataset encoding"""
        service_map = {
            'http': 0, 'dns': 1, 'smtp': 2, 'ftp': 3, 'ssh': 4, 
            'dhcp': 5, 'ssl': 6, 'irc': 7, 'unknown': 8
        }
        return service_map.get(service.lower(), 8)
    
    def _encode_state(self, state):
        """Encode connection state to match UNSW dataset encoding"""
        state_map = {
            'fin': 0, 'con': 1, 'int': 2, 'acc': 3, 'clo': 4, 'rst': 5, 'unknown': 6
        }
        return state_map.get(state.lower(), 6)
    
    def _encode_http_method(self, method):
        """Encode HTTP method"""
        method_map = {
            'get': 0, 'post': 1, 'put': 2, 'delete': 3, 'head': 4, 'options': 5, 'unknown': 6
        }
        return method_map.get(method.lower(), 6)
    
    def _is_private_ip(self, ip_str):
        """Check if an IP address is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    def _extract_log_data(self, request):
        """
        Extract data from request to approximate UNSW-NB15 dataset features.
        Many network-level features will be estimated or set to defaults.
        
        Args:
            request (dict): Request information dictionary
            
        Returns:
            dict: Log data approximating UNSW dataset columns
        """
        # Extract protocol from request
        protocol = 'tcp'  # Default to TCP
        
        # Default/estimated values for network-level features
        log_data = {
            # Using the proper key names that match _extract_features method
            'dur': 0.0,
            'proto': self._encode_protocol(protocol),
            'service': self._encode_service('http'),
            'state': self._encode_state('con'),
            
            # Packet statistics - using consistent key names
            'spkts': 1,
            'dpkts': 0,
            'sbytes': request.get('content_length', 0),
            'dbytes': 0,
            
            # Connection rate
            'rate': 0,
            
            # TTL values (default)
            'sttl': 64,
            'dttl': 64,
            
            # Load metrics
            'sload': 0.0,
            'dload': 0.0,
            
            # Packet timing
            'sinpkt': 0.0,
            'dinpkt': 0.0,
            'sjit': 0.0,
            'djit': 0.0,
            
            # TCP window info
            'swin': 65535,
            'dwin': 65535,
            'stcpb': 0,
            'dtcpb': 0,
            
            # Round trip time
            'tcprtt': 0.0,
            'synack': 0.0,
            'ackdat': 0.0,
            
            # Source and destination IPs
            'src_ip': request.get('ip', '0.0.0.0'),
            'dst_ip': request.get('server_ip', '0.0.0.0'),
            
            # Connection counts - using the same key names as in _extract_features
            'ct_srv_src': 1,
            'ct_dst_ltm': 1,
            'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 1,
            'ct_dst_src_ltm': 1,
            'ct_src_ltm': 1,
            'ct_srv_dst': 1,
        }
        
        return log_data
    
    def check_blocklist(self, ip):
        """
        Check if an IP is in the blocklist
        
        Args:
            ip (str): IP address to check
            
        Returns:
            bool: True if IP is blocked, False otherwise
        """
        return ip in self.blocklist
    
    def add_to_blocklist(self, ip):
        """
        Add an IP to the blocklist
        
        Args:
            ip (str): IP address to block
            
        Returns:
            bool: True if added successfully, False otherwise
        """
        try:
            self.blocklist.add(ip)
            self._save_blocklist()
            logger.info(f"Added {ip} to blocklist")
            return True
        except Exception as e:
            logger.error(f"Failed to add {ip} to blocklist: {e}")
            return False
    
    def mediate_request(self, request):
        """
        Main function to mediate incoming API requests
        
        Args:
            request (dict): Information about the incoming request
            
        Returns:
            dict: Response with decision (allow/block)
        """
        ip = request.get('ip', '0.0.0.0')
        origin = request.get('origin', 'unknown')
        
        # Check if IP is already blocked
        if self.check_blocklist(ip):
            logger.info(f"Blocked request from {ip} (in blocklist)")
            return {
                'status': 'blocked',
                'reason': 'IP in blocklist',
                'ip': ip
            }
        
        # Check if we want to analyze this particular origin
        if origin  in ['monitored_origin_1', 'monitored_origin_2']:  # Corrected logic!
            logger.info(f"Allowed request from non-monitored origin {origin}")
            return {
                'status': 'allowed',
                'reason': 'Origin not monitored',
                'ip': ip
            }
        
        # Extract log data
        log_data = self._extract_log_data(request)
        print(log_data)
        # Transform log data into UNSW dataset features
        features_df = self._extract_features(request, log_data)
        
        try:
            # Predict using the model
            is_anomaly = self.model.predict(features_df)[0]
            
            if is_anomaly == 1:  # Assuming 1 means anomaly in your model
                self.add_to_blocklist(ip)
                logger.warning(f"Detected anomaly from {ip}, added to blocklist")
                return {
                    'status': 'blocked',
                    'reason': 'Anomaly detected',
                    'ip': ip
                }
            else:
                logger.info(f"Normal activity from {ip}")
                return {
                    'status': 'allowed',
                    'reason': 'Normal activity',
                    'ip': ip
                }
                
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            # In case of error, allow the request but log the issue
            return {
                'status': 'allowed',
                'reason': 'Prediction error',
                'ip': ip
            }


# Example usage
def create_mediator(model_path, blocklist_path):
    """Factory function to create an instance of the mediator"""
    return AnomalyDetectionMediator(model_path, blocklist_path)


# Example request handler function
def handle_api_request(request, mediator):
    """
    Handle an incoming API request with anomaly detection
    
    Args:
        request (dict): Information about the request
        mediator (AnomalyDetectionMediator): Mediator instance
        
    Returns:
        tuple: (response, status_code)
    """
    # Check for anomalies
    mediation_result = mediator.mediate_request(request)
    
    if mediation_result['status'] == 'blocked':
        # Return a blocked response
        return {
            'error': 'Access denied',
            'message': 'Your IP has been blocked due to suspicious activity'
        }, 403
    
    # Process the request normally if not blocked
    # ... Your normal request processing logic here ...
    
    return {
        'status': 'success',
        'message': 'Request processed successfully'
    }, 200


# Example implementation in a Flask API
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

# Initialize the mediator
mediator = create_mediator('path/to/model.pkl', 'path/to/blocklist.txt')

@app.route('/api/resource', methods=['GET', 'POST'])
def api_endpoint():
    # Prepare request info
    request_info = {
        'ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'query_params': request.args.to_dict(),
        'headers': dict(request.headers),
        'content_length': request.content_length or 0,
        'origin': request.headers.get('Origin', 'unknown'),
        'protocol': 'https' if request.is_secure else 'http',  # Fixed this line
        'server_ip': request.host
    }
    
    # Process through mediator
    response, status_code = handle_api_request(request_info, mediator)
    
    return jsonify(response), status_code

if __name__ == '__main__':
    app.run(debug=True)
"""
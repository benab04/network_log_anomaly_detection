from django.shortcuts import render
from django.http import JsonResponse
from datetime import datetime, time
import pandas as pd
import json
import numpy as np
# from main import AnomalyDetectionMediator, create_mediator, handle_api_request
import pickle
# Create your views here.


import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

def preprocess_df(df):
    # 1. Drop columns not needed for training
    
    # 2. Clamp extreme values in numeric columns
    df_numeric = df.select_dtypes(include=[np.number])
    for feature in df_numeric.columns:
        if df_numeric[feature].max() > 10 * df_numeric[feature].median() and df_numeric[feature].max() > 10:
            df[feature] = np.where(
                df[feature] < df[feature].quantile(0.95),
                df[feature],
                df[feature].quantile(0.95)
            )
    
    # 3. Log transform highly skewed numeric features
    for feature in df_numeric.columns:
        if df_numeric[feature].nunique() > 50:
            if df_numeric[feature].min() == 0:
                df[feature] = np.log(df[feature] + 1)
            else:
                df[feature] = np.log(df[feature])
    
    # 4. Simplify high-cardinality categorical features
    df_cat = df.select_dtypes(exclude=[np.number])
    for feature in df_cat.columns:
        if df_cat[feature].nunique() > 6:
            top_values = df[feature].value_counts().head().index
            df[feature] = np.where(df[feature].isin(top_values), df[feature], '-')
    
    # 5. Separate features and target
    X = df # All columns except the last as features
    
    # 6. Identify categorical columns for encoding
    cat_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()
    
    # 7. ColumnTransformer for encoding and scaling
    ct = ColumnTransformer(
        transformers=[
            ('encoder', OneHotEncoder(handle_unknown='ignore'), cat_cols)
        ],
        remainder='passthrough'
    )
    X_processed = ct.fit_transform(X)
    
    # 8. Scale numeric features (after encoding)
    # Find the index where numeric features start (after one-hot encoded columns)
    n_cat_features = ct.transformers_[0][1].fit(X[cat_cols]).get_feature_names_out().shape[0]
    scaler = StandardScaler()
    X_processed = np.array(X_processed, dtype=np.float64)
    X_processed[:, n_cat_features:] = scaler.fit_transform(X_processed[:, n_cat_features:])
    
    return X_processed

# Usage:
# X, y = preprocess_df(df)


# Example usage:
# X_transformed, feature_names = transform_network_log_data(df)


def home_page(request):
    return JsonResponse({"message": "Welcome to the home page!"})


def _load_model(model_path):
    """Load the trained anomaly detection model"""
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        raise   

def json_to_dataframe(json_data):

    # Extract the log data from the JSON

    log_data = json_data.get('log', {})

    

    # Convert the log data to a single row DataFrame

    df = pd.DataFrame([log_data])
    
    return df


def get_time (request):
    
    if request.method != 'POST':
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")

    # mediator = create_mediator('rf_model.pkl', 'blocklist.txt')
    ## Process through mediator
    # response, status_code = handle_api_request(request_info, mediator)
    
    # print(response, status_code)
    model =_load_model('rf_model_2.pkl')
    
    try:
        request_body = request.body.decode('utf-8')
        
        df= json_to_dataframe(json.loads(request_body)) 
        
        # Rearrange the columns to match the specified order
        desired_order = ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes',
                            'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
                            'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin',
                            'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth',
                            'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
                            'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
                            'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
                            'ct_srv_dst', 'is_sm_ips_ports']




        # Rearrange the columns
        df = df[desired_order]
        print("Columns at indices 1, 2, 3:", df.columns[[1,2,3]])
        # num_existing_columns = df.shape[1]
        # num_additional_columns = 14
        # num_total_columns = 56

        # # Insert 14 padding columns at the beginning
        # for i in range(num_additional_columns):
        #     df.insert(0, f'Padding_{i+1}', np.nan)

        # # Add more columns at the end if needed to reach 56 columns
        # while df.shape[1] < num_total_columns:
        #     df[f'Extra_{df.shape[1] + 1}'] = np.nan

        print(df.shape)  # Should print (num_rows, 56)
        df = preprocess_df(df)
        
        print(df.shape) 
        
        y = model.predict(df)
        
        print("Output: ", y)
        
    except Exception as e:
        print("Error decoding request body:", str(e))
        
        
    return JsonResponse({"time": current_time})
    




def _extract_log_data(self, request):
    """
    Extract data from Django request to approximate UNSW-NB15 dataset features.
    Many network-level features will be estimated or set to defaults.
    
    Args:
        request (dict): Request information dictionary from Django request
        
    Returns:
        dict: Log data approximating UNSW dataset columns
    """
    now = datetime.now()
    
    # Default/estimated values for network-level features
    log_data = {
        # Basic flow features
        'dur': 0.0,  # Duration - will need to be updated after response
        'proto': self._encode_protocol(request.get('protocol', 'tcp')),
        'service': self._encode_service('http'),  # Web service
        'state': self._encode_state('con'),  # Connection state
        
        # Packet statistics
        'spkts': 1,  # Source packets - default to 1 for request
        'dpkts': 0,  # Destination packets - will be set after response
        'sbytes': request.get('content_length', 0),  # Source bytes
        'dbytes': 0,  # Destination bytes - will be set after response
        
        # Connection rate
        'rate': 0,  # Requires historical data
        
        # TTL values (default)
        'sttl': 64,  # Source TTL
        'dttl': 64,  # Destination TTL
        
        # Load metrics
        'sload': 0.0,  # Source bits per second
        'dload': 0.0,  # Destination bits per second
        'sloss': 0,  # Source packets retransmitted/dropped
        'dloss': 0,  # Destination packets retransmitted/dropped
        
        # Packet timing
        'sinpkt': 0.0,  # Source inter-packet arrival time
        'dinpkt': 0.0,  # Destination inter-packet arrival time
        'sjit': 0.0,  # Source jitter
        'djit': 0.0,  # Destination jitter
        
        # TCP window info
        'swin': 65535,  # Source TCP window
        'dwin': 65535,  # Destination TCP window
        'stcpb': 0,  # Source TCP base sequence number
        'dtcpb': 0,  # Destination TCP base sequence number
        
        # Round trip time
        'tcprtt': 0.0,  # TCP connection setup round-trip time
        'synack': 0.0,  # TCP connection setup time (SYN to SYN-ACK)
        'ackdat': 0.0,  # TCP connection setup time (SYN-ACK to ACK)
        
        # Average packet size
        'smean': request.get('content_length', 0),  # Mean source packet size
        'dmean': 0,  # Mean destination packet size
        
        # HTTP transaction info
        'trans_depth': 1,  # HTTP transaction depth
        'response_body_len': 0,  # HTTP response body size
        
        # Connection counts
        'ct_srv_src': 1,  # Connection count to same service from source 
        'ct_state_ttl': 1,  # Connection count of states and TTL values
        'ct_dst_ltm': 1,  # Connection count to destination in last 100
        'ct_src_dport_ltm': 1,  # Same destination port connections from source
        'ct_dst_sport_ltm': 1,  # Same source port connections from destination
        'ct_dst_src_ltm': 1,  # Connections between same src and dst
        'ct_src_ltm': 1,  # Connections from source in last 100
        'ct_srv_dst': 1,  # Connections to same service from destination
        
        # FTP-specific features
        'is_ftp_login': 0,  # FTP session has login attempt
        'ct_ftp_cmd': 0,  # Count of FTP commands
        
        # HTTP method count
        'ct_flw_http_mthd': 1,  # Count of HTTP methods in flow
        
        # Port info
        'is_sm_ips_ports': 0,  # Same IP addresses and port numbers
    }
    
    return log_data
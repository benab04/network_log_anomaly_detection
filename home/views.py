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

def transform_network_log_data(df):
    """
    Transform a dataframe containing 42 network log features into a dataframe with 56 features
    by one-hot encoding categorical variables (proto, service, state) and applying preprocessing.
    
    Parameters:
    df (pandas.DataFrame): Input dataframe with 42 features
    
    Returns:
    numpy.ndarray: Transformed data with 56 features
    list: Feature names in the transformed data
    """
    # Check if we have the expected number of input features
    if len(df.columns) != 42:
        raise ValueError(f"Expected 42 features, but got {len(df.columns)}")
    
    # Create a new dataframe with specific structure needed for the transformation
    # Assuming the first columns need to be categorical for one-hot encoding
    # This mimics the structure in the original code where categorical columns were at positions 1, 2, 3
    # First, identify categorical columns - typical ones in network logs are proto, service, state
    categorical_columns = []
    
    # Create a structured dataframe for processing
    # In network data, typically proto, service, and state are categorical
    # We'll place these as the first 3 columns
    transformed_df = pd.DataFrame()
    
    # Add the proto column (assuming it exists in input df)
    if 'proto' in df.columns:
        transformed_df['proto'] = df['proto']
        categorical_columns.append('proto')
    else:
        # Create a placeholder if the original column name isn't found
        transformed_df['proto'] = 'unknown'
        categorical_columns.append('proto')
    
    # Add the service column
    if 'service' in df.columns:
        transformed_df['service'] = df['service']
        categorical_columns.append('service')
    else:
        transformed_df['service'] = '-'
        categorical_columns.append('service')
    
    # Add the state column
    if 'state' in df.columns:
        transformed_df['state'] = df['state']
        categorical_columns.append('state')
    else:
        transformed_df['state'] = '-'
        categorical_columns.append('state')
    
    # Add all numeric features
    for col in df.columns:
        if col not in categorical_columns:
            transformed_df[col] = df[col]
    
    # Create X dataframe without the label column (assuming label is at the end)
    # If there's no label column, we'll use all columns
    X = transformed_df
    
    # Get starting feature names for tracking
    original_feature_names = list(X.columns)
    
    # One-hot encode the categorical columns (proto, service, state)
    categorical_indices = [0, 1, 2]  # Indices of categorical columns in the transformed_df
    ct = ColumnTransformer(
        transformers=[('encoder', OneHotEncoder(), categorical_indices)], 
        remainder='passthrough'
    )
    X_transformed = np.array(ct.fit_transform(X))
    
    # Create feature names list
    feature_names = []
    
    # Find the unique values for each categorical feature to build the feature names
    cat_features = ['proto', 'service', 'state']
    for i, col in enumerate(cat_features):
        unique_values = X[col].unique()
        for val in unique_values[::-1][1:]:  # Skip the reference category
            feature_names.append(f"{col}_{val}")
    
    # Add the names of the passthrough columns
    for col in original_feature_names[3:]:
        feature_names.append(col)
    
    # Apply scaling to numerical features (everything after one-hot encoded columns)
    # Get the number of encoded columns
    n_encoded_cols = X_transformed.shape[1] - len(original_feature_names) + 3
    
    # Create a scaler
    scaler = StandardScaler()
    
    # Create a copy to avoid modifying the original array
    X_scaled = X_transformed.copy()
    
    # Scale only the numerical columns
    X_scaled[:, n_encoded_cols:] = scaler.fit_transform(X_transformed[:, n_encoded_cols:])
    
    return X_scaled, feature_names

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
        # X, features = transform_network_log_data(df)
        from sklearn.compose import ColumnTransformer
        from sklearn.preprocessing import OneHotEncoder
        ct = ColumnTransformer(transformers=[('encoder', OneHotEncoder(), [1,2,3])], remainder='passthrough')
        df = np.array(ct.fit_transform(df))
        print(np.shape(df))
        
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
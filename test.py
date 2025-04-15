import json
import pandas as pd

request_body={
  "api_key": "your_api_key_here",
  "model": "network_anomaly_detector_v1",
  "session_id": "sess_12345abcde",
  "timestamp": "2025-04-15T14:30:45Z",
  "client_info": {
    "ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "country": "US"
  },
  "request_metadata": {
    "method": "POST",
    "path": "/api/v1/data",
    "content_length": 2048,
    "protocol": "https"
  },
  "log": {
    "dur": 0.0,
    "proto": 0,
    "service": 0,
    "state": 1,
    "spkts": 1,
    "dpkts": 0,
    "sbytes": 2048,
    "dbytes": 0,
    "rate": 0,
    "sttl": 64,
    "dttl": 64,
    "sload": 0.0,
    "dload": 0.0,
    "sloss": 0,
    "dloss": 0,
    "sinpkt": 0.0,
    "dinpkt": 0.0,
    "sjit": 0.0,
    "djit": 0.0,
    "swin": 65535,
    "dwin": 65535,
    "stcpb": 0,
    "dtcpb": 0,
    "tcprtt": 0.0,
    "synack": 0.0,
    "ackdat": 0.0,
    "smean": 2048,
    "dmean": 0,
    "trans_depth": 1,
    "response_body_len": 0,
    "ct_srv_src": 1,
    "ct_state_ttl": 1,
    "ct_dst_ltm": 1,
    "ct_src_dport_ltm": 1,
    "ct_dst_sport_ltm": 1,
    "ct_dst_src_ltm": 1,
    "ct_src_ltm": 1,
    "ct_srv_dst": 1,
    "is_ftp_login": 0,
    "ct_ftp_cmd": 0,
    "ct_flw_http_mthd": 1,
    "is_sm_ips_ports": 0
  }
}


def json_to_dataframe(json_data):

    # Extract the log data from the JSON

    log_data = json_data.get('log', {})

    

    # Convert the log data to a single row DataFrame

    df = pd.DataFrame([log_data])
    
    return df


df= json_to_dataframe(request_body) 

print(df.head())
import numpy as np
np.shape(df)




from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
ct = ColumnTransformer(transformers=[('encoder', OneHotEncoder(), [1,2,3])], remainder='passthrough')
X = np.array(ct.fit_transform(df))
X.shape


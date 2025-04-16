from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import joblib
import pickle
import warnings

warnings.filterwarnings("ignore")

def process(df):
    # Rearrange the columns to match the specified order
    desired_order = ['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes',
                            'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
                            'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin',
                            'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth',
                            'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
                            'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
                            'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm',
                            'ct_srv_dst', 'is_sm_ips_ports']

    # Keep only the columns in desired_order (ignore extras in df)
    df = df[[col for col in desired_order if col in df.columns]]


    # Rearrange the columns
    df = df[desired_order]

    df_numeric = df.select_dtypes(include=[np.number])

    for feature in df_numeric.columns:
        if df_numeric[feature].max()>10*df_numeric[feature].median() and df_numeric[feature].max()>10 :
            df[feature] = np.where(df[feature]<df[feature].quantile(0.95), df[feature], df[feature].quantile(0.95))
            
    df_numeric = df.select_dtypes(include=[np.number])

    df_before = df_numeric.copy()

    for feature in df_numeric.columns:
        if df_numeric[feature].nunique()>50:
            if df_numeric[feature].min()==0:
                df[feature] = np.log(df[feature]+1)
            else:
                df[feature] = np.log(df[feature])

    df_numeric = df.select_dtypes(include=[np.number])

    df_cat = df.select_dtypes(exclude=[np.number])

    for feature in df_cat.columns:
        if df_cat[feature].nunique()>6:
            df[feature] = np.where(df[feature].isin(df[feature].value_counts().head().index), df[feature], '-')
            

    df_cat = df.select_dtypes(exclude=[np.number])
    df.loc[:, 'proto'] = df['proto'].astype(str)
    df.loc[:, 'service'] = df['service'].astype(str)
    df.loc[:, 'state'] = df['state'].astype(str)
    X = df


    ct = joblib.load('column_transformer.pkl')
    X = np.array(ct.transform(X))

    sc = StandardScaler() 
    X[:, 18:] = sc.fit_transform(X[:, 18:])
    
    return X


def json_to_dataframe(json_data):


    log_data = json_data.get('log', {})

    # Convert the log data to a single row DataFrame

    df = pd.DataFrame([log_data])
    
    return df


def _load_model(model_path):
    """Load the trained anomaly detection model"""
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        raise   

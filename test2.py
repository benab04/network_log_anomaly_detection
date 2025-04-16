from sklearn.datasets import make_classification
from joblib import dump, load
import pickle
import time
import os

def _load_model(model_path):
    """Load the trained anomaly detection model"""
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        raise   
model = _load_model('rf_model_2.pkl')
dump(model, 'model.joblib', compress=3)

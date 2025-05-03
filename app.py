import streamlit as st
import joblib
import numpy as np
import re
from urllib.parse import urlparse

st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")

# Load the XGBoost model
@st.cache_resource
def load_model(model_path='xgb_model.pkl'):
    try:
        model = joblib.load(model_path)
        return model
    except FileNotFoundError:
        st.error("Model file not found!")
        return None

# Feature extraction function
def extract_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""
    path = parsed_url.path if parsed_url.path else ""

    features = {
        'Have_IP': 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0,
        'Have_At': 1 if '@' in url else 0,
        'URL_Length': len(url),
        'URL_Depth': path.count('/'),
        'Redirection': 1 if '//' in url[7:] else 0,
        'https_Domain': 1 if 'https' in parsed_url.scheme else 0,
        'TinyURL': 1 if 'tinyurl' in url else 0,
        'Prefix/Suffix': 1 if '-' in hostname else 0,
        'DNS_Record': 1 if hostname != '' else 0,
        'Web_Traffic': 1 if len(url) > 20 else 0,
        'Domain_Age': 1 if len(hostname.split('.')) > 2 else 0,
        'Domain_End': 1 if hostname.endswith(('.com', '.org', '.net')) else 0,
        'iFrame': 1 if '<iframe' in url else 0,
        'Mouse_Over': 1 if 'mouseover' in url else 0,
        'Right_Click': 1 if 'rightclick' in url else 0,
        'Web_Forwards': 1 if 'forward' in url else 0,
    }
    return list(features.values())

# Prediction function
def predict_url_safety(url):
    model = load_model()
    if model is None:
        return "error"
    
    features = extract_features(url)
    features_array = np.array(features).reshape(1, -1)
    prediction = model.predict(features_array)
    
    return "safe" if prediction[0] == 0 else "not safe"

# Custom HTML style blocks
st.markdown("""
    <style>
    .title {
        text-align: center;
        font-size: 2.5em;
        color: #4CAF50;
    }
    .safe-box {
        background-color: #d4edda;
        color: #155724;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #c3e6cb;
        font-size: 18px;
        text-align: center;
    }
    .unsafe-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #f5c6cb;
        font-size: 18px;
        text-align: center;
    }
    </style>
""", unsafe_allow_html=True)

# App Title
st.markdown('<h1 class="title"> Phishing URL Detection Website</h1>', unsafe_allow_html=True)
st.write("Detect suspicious websites in real-time and browse with confidence.")
st.write("Enter a website URL below to check if it's safe or potentially dangerous.")



# Input form
url_input = st.text_input("🔗 URL to Check:", "")

if st.button(" Analyze URL"):
    if url_input:
        result = predict_url_safety(url_input)
        if result == "safe":
            st.markdown('<div class="safe-box">✅ The URL appears to be <strong>SAFE</strong>.</div>', unsafe_allow_html=True)
        elif result == "not safe":
            st.markdown('<div class="unsafe-box">⚠️ The URL is likely <strong>NOT SAFE</strong>. Proceed with caution!</div>', unsafe_allow_html=True)
        else:
            st.error("Model not found or something went wrong.")
    else:
        st.warning("Please enter a valid URL to analyze.")
st.markdown("""
### Protect Yourself from Phishing Attacks  
🌐 Check any URL before you click  
⚠️ Instantly know if a site is Safe or Suspicious  
🤖 Powered by Machine Learning  
🚀 Fast, Simple, and Reliable Detection  
""")

# Phishing Website Detection

##  About the Project
Phishing attacks are a growing cybersecurity threat, and this Phishing Website Detection project provides a fast and effective way to identify potentially unsafe websites. By leveraging machine learning (XGBoost) and integrating a Flask backend with a simple HTML, CSS, and JavaScript frontend, this tool offers an easy-to-use solution for users to verify website safety.
##  Features
- **URL-based feature extraction** (e.g., presence of IP, URL length, redirections, etc.).
- **Machine Learning model (XGBoost) for classification**.
- **Joblib for model storage and loading**.
- **User Interface (GUI or Chrome Extension) for easy access**.
- **Colorblind-friendly UI design**.

##  Tech Stack
- **Frontend**: HTML, CSS, JavaScript  
- **Backend**: Python, Flask  
- **Machine Learning**: XGBoost, Scikit-Learn  
- **Model Deployment**: Flask API  
- **Storage**: Joblib for model saving/loading 

##  Dataset & Features
The model is trained on a dataset with features such as:
- `Have_IP`, `Have_At`, `URL_Length`, `URL_Depth`
- `Redirection`, `https_Domain`, `TinyURL`, `Prefix/Suffix`
- `DNS_Record`, `Web_Traffic`, `Domain_Age`, `Domain_End`
- `iFrame`, `Mouse_Over`, `Right_Click`, `Web_Forwards`

##  How to Run
1. **Clone the repository**  
   ```bash
   git clone https://github.com/ManasaVeera79/phishing-website-detection.git
   cd phishing-website-detection
2. **Create a Virtual Environment and Install Dependencies**
   ```bash
   python -m venv venv
   source venv/bin/activate  # (On Windows: venv\Scripts\Activate)
   pip install -r requirements.txt
3. **Run the Flask Backend**
   ```bash
   python app.py
4. **Open the Frontend**
- Open index.html in a web browser.
- Enter a website URL and click "Check", it gives url is safe or unsafe.
- The result will be displayed after the backend processes the request.

# ☁️ Cloud Data Leakage Detection System Using Machine Learning

A web-based **Data Loss Prevention (DLP)** system that uses **Machine Learning, NLP, and rule-based detection** to identify and prevent potential leakage of sensitive information from text and uploaded documents.

## 🎯 Objective

The main objective of this project is to detect sensitive information such as personal, financial, and confidential data before it can be unintentionally exposed.

The system analyzes text and documents and classifies them as **SAFE** or **potential LEAK**, assigns a risk score, and quarantines suspicious files for administrator review.

---

## 🚀 Key Features

* 🔍 **Text Scanning** – Detect sensitive information from user-entered text.
* 📄 **File Scanning** – Analyze PDF, DOCX and TXT files.
* 🧩 **Rule-Based Detection** – Regex-based detection of PII and secrets.
* 🤖 **Machine Learning** – Classify content as Safe or Leak.
* 🌲 **Random Forest** – Primary ML classification model.
* 📊 **TF-IDF** – Convert text into numerical features.
* 🧠 **NER** – Identify entities using spaCy.
* 📈 **Risk Scoring** – Generate a risk score from 0–100.
* 🔒 **File Encryption** – Encrypt potentially sensitive files.
* 🚨 **Quarantine** – Isolate potential data leaks for admin review.
* 🛡️ **Security Monitoring** – Attack logs, failed-login protection and honeypot.
* 👨‍💼 **Admin Dashboard** – Monitor users, scans, risks and security events.
* 📚 **Scan History & Analytics** – Track previous scanning activity.
* 🔌 **REST API** – Enable programmatic text scanning.
* 📑 **Reporting** – Export security information to PDF and CSV.

---

## 🛠️ Tech Stack

### Backend

* **Python**
* **Flask**

### Machine Learning & NLP

* **Scikit-learn**
* **TF-IDF**
* **Random Forest**
* **Logistic Regression**
* **Support Vector Machine (SVM)**
* **spaCy / NER**
* **Regular Expressions**

### File Processing & Security

* **PyPDF2**
* **python-docx**
* **Cryptography / Fernet**
* **SQLite**

### Frontend

* **HTML5**
* **CSS3**
* **JavaScript**

### Development

* **Git**
* **GitHub**
* **Python Virtual Environment**

---

## 🧠 Machine Learning Approach

The system uses **TF-IDF** for text feature extraction and multiple classification algorithms:

```text
Input Text
    ↓
Text Preprocessing
    ↓
TF-IDF Vectorization
    ↓
┌──────────────┬──────────────┬──────────────┐
│ Random Forest│   Logistic   │     SVM      │
│              │  Regression  │              │
└──────────────┴──────────────┴──────────────┘
                    ↓
              SAFE / LEAK
```

**Random Forest** is used as the primary classifier in the scanning workflow.

The models can be evaluated using:

* Accuracy
* Precision
* Recall
* F1 Score

---

## 🔍 Detection Workflow

```text
User
 ↓
Text Input / File Upload
 ↓
Text Extraction
 ↓
┌────────────┬────────────┬────────────┐
│   Regex    │     ML     │    NER     │
│ Detection  │ Detection  │  (spaCy)   │
└────────────┴────────────┴────────────┘
             ↓
        Risk Analysis
             ↓
       Risk Score 0–100
             ↓
       ┌─────┴─────┐
       ↓           ↓
     SAFE         LEAK
                    ↓
               Encryption
                    ↓
               Quarantine
                    ↓
              Admin Review
```

---

## 🔐 Sensitive Data Detection

The system can detect patterns associated with:

* Email addresses
* Phone numbers
* Aadhaar numbers
* PAN numbers
* Credit card numbers
* Bank account numbers
* Passport numbers
* SSN patterns
* API keys
* JWT tokens
* Passwords and secrets
* Private keys
* Voter ID patterns

> **Note:** Pattern-based detection identifies data that resembles a sensitive format. It does not verify whether identifiers such as Aadhaar or PAN numbers are genuine.

---

## 🚨 Risk & Quarantine

When potentially sensitive information is detected, the system calculates a risk score.

For example:

```text
Risk Score: 55 / 100
Risk Level: Medium Risk
ML Prediction: LEAK
Confidence: 58.7%
```

If a file is classified as a potential leak:

```text
File
 ↓
Detection
 ↓
Risk Analysis
 ↓
LEAK
 ↓
Fernet Encryption
 ↓
Quarantine
 ↓
Administrator Review
```

This provides an additional layer of protection against accidental data exposure.

---

## 🛡️ Security Features

The application includes:

* User registration and login
* Password hashing
* Failed-login protection
* Account locking
* Attack logging
* Honeypot monitoring
* File encryption
* File quarantine
* Scan history
* Admin dashboard
* Security analytics

---

## 📂 Project Structure

```text
Cloud-Data-Leakage-Detection-System-using-Machine-Learning/
│
├── app.py
├── requirements.txt
├── .gitignore
├── static/
├── templates/
│   ├── admin.html
│   ├── dashboard.html
│   ├── history.html
│   ├── scan_text.html
│   ├── upload.html
│   └── ...
│
├── uploads/
└── quarantine/
```

Runtime files such as the local database, uploads, quarantine files and virtual environment are excluded from GitHub using `.gitignore`.

---

## ⚙️ How to Run

### 1. Clone the repository

```bash
git clone https://github.com/aarshiyasultana10-max/Cloud-Data-Leakage-Detection-System-using-Machine-Learning.git
```

### 2. Enter the project directory

```bash
cd Cloud-Data-Leakage-Detection-System-using-Machine-Learning
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate it

**Windows:**

```cmd
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python app.py
```

### 7. Open in browser

```text
http://127.0.0.1:5000
```

---

## 🔮 Future Enhancements

* ☁️ Deploy on AWS / Azure / Google Cloud
* 🔄 Real-time cloud storage monitoring
* 📧 Email and file-sharing DLP integration
* 🧠 Advanced deep-learning models
* 🎯 Context-aware PII detection
* 📉 Reduce false positives
* 🔐 Advanced role-based access control
* 🚨 Real-time security alerts
* 📊 Advanced threat analytics

---

## 👩‍💻 Author

**Arshiya Sultana**

Bachelor of Engineering — Artificial Intelligence and Data Science

**Project:** Cloud Data Leakage Detection System Using Machine Learning

**Domain:** Cybersecurity • Machine Learning • NLP • Data Loss Prevention

# Cloud Data Leakage Detection System Using Machine Learning

## 📌 Overview

Cloud Data Leakage Detection System Using Machine Learning is a web-based Data Loss Prevention (DLP) system designed to identify and prevent the accidental leakage of sensitive information from text and uploaded documents.

The system combines rule-based detection, machine learning, and Named Entity Recognition (NER) to analyze content and determine whether it contains potentially sensitive information.

## 🎯 Objectives

- Detect sensitive and confidential information.
- Identify potential data leakage in text and documents.
- Use machine learning to classify content as Safe or Leak.
- Calculate a risk score for detected content.
- Encrypt and quarantine potentially leaked files.
- Maintain security and scan history.
- Provide administrators with monitoring and management capabilities.

## 🔍 Sensitive Data Detection

The system uses rule-based pattern detection to identify information such as:

- Email addresses
- Phone numbers
- Aadhaar numbers
- PAN numbers
- Credit card numbers
- Bank account numbers
- Passport numbers
- SSN
- API keys
- JWT tokens
- Passwords and secrets
- Private keys
- Voter ID

> Note: Pattern-based detection identifies information that matches sensitive-data formats. It does not verify whether the identified number is genuine or belongs to a real person.

## 🤖 Machine Learning

The system uses machine learning to classify content as potentially **SAFE** or **LEAK**.

### Text Processing

Text is converted into numerical features using **TF-IDF (Term Frequency-Inverse Document Frequency)**.

### Machine Learning Models

The project includes:

- Random Forest
- Logistic Regression
- Support Vector Machine (SVM)

Random Forest is used as the primary classifier during the scanning process.

The models can be evaluated using:

- Accuracy
- Precision
- Recall
- F1 Score

## 🧠 Named Entity Recognition

The system uses **spaCy Named Entity Recognition (NER)** to identify entities in the scanned content, including:

- PERSON
- ORGANIZATION
- LOCATION/GPE
- MONEY
- CARDINAL

NER provides additional contextual information during analysis.

## 📊 Risk Scoring

After scanning, the system generates a risk score from **0 to 100**.

The score considers factors such as:

- Rule-based detections
- Machine learning prediction
- ML confidence
- File-related characteristics

The system categorizes detected content according to its calculated risk.

## 🔐 File Protection and Quarantine

When an uploaded file is identified as a potential data leak, the system can:

1. Detect sensitive information.
2. Calculate the risk score.
3. Classify the file as a potential leak.
4. Encrypt the file using Fernet encryption.
5. Move the file to the quarantine area.
6. Record the event for administrator review.

This prevents potentially sensitive files from continuing through the normal workflow until they have been reviewed.

## 📄 Supported File Processing

The system can process text from common document formats such as:

- PDF
- DOCX
- TXT

For example:

```text
Uploaded File
     ↓
Text Extraction
     ↓
Sensitive Data Detection
     ↓
ML Classification
     ↓
NER Analysis
     ↓
Risk Score
     ↓
SAFE / LEAK

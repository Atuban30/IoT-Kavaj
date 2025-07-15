# 🔐 IoT KAVAJ – DDoS Attack Detection in IoT Networks Using Machine Learning

**IoT KAVAJ** is our final year project focused on enhancing the security of IoT environments by detecting Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks using a machine learning-based approach. The core of our solution is a **Stacking Ensemble ML Model** combining the strengths of **XGBoost**, **Logistic Regression**, and **Random Forest** to provide accurate real-time detection of attacks.

---

## 🚀 Project Overview

- A **controlled DoS attack simulation** was conducted to generate malicious network traffic.
- Network packets were captured using **Scapy**, a powerful packet manipulation tool in Python.
- The captured data was analyzed, processed, and labeled (`0` for attacked, `1` for non-attacked) to create the training dataset.
- The trained **Stacked Ensemble Model** achieved **98% accuracy** and was able to detect attacks in a **real-time scenario**, triggering an alert to the user.

---

## ⚙️ Tech Stack and Tools Used

- **Programming Languages:** Python (Scapy, Sklearn, XGBoost), C/C++ (Arduino), HTML/CSS (Flask UI)
- **ML Frameworks:** scikit-learn, XGBoost
- **Hardware:** ESP32 microcontroller, DHT11 sensor
- **Tools:** Wireshark, hping3, Metasploit, Flask, MongoDB
- **Data Monitoring:** Scapy for live packet capture and labeling

---

## 🧪 Project Structure
IoT_KAVAJ/
├── Arduino_Code/ # ESP32 and sensor setup
├── Attack_Scripts/ # DoS attack simulation
├── Scapy_Script/ # Data sniffing and labeling
├── ML_Model/ # Stacking Ensemble model training notebook
├── Database/ # Dataset used for training
├── Normal Data fetch script/ # Collecting normal data from ESP32
└── README.md # Project description and usage terms


---

## ⚠️ Disclaimer

> ⚠️ The attack scripts and techniques provided in this repository are strictly for **educational and research purposes** within a **controlled and isolated environment** only.  
> Unauthorized use, replication, or deployment of these scripts in real-world systems or against any networks without explicit permission is illegal and unethical.  
> The project authors hold **no responsibility** for any misuse or unintended consequences of these materials.

---

## 📈 Results

- **Model Accuracy:** 98%
- **Real-time Detection:** Successfully detected DoS attacks on live network traffic.
- **Stacked Model Output:** Superior accuracy and low false-positive rate compared to individual models.

---

## 🤝 Contributions

This project was developed collaboratively as part of our final year research initiative under the specialization in **Cybersecurity and Forensics**.

---

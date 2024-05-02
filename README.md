# Intrusion-Detection-System
Hybrid of Signature and Anomaly Detection

System Requirements:
GPU: Greater than 2GB,
RAM: 4GB or higher,
CPU: Core i5 and above,
Operating System: Windows 10, 11, Linux
Python Version: 3.8 and above

Installation Requied Packages: pip install -r requirements.txt

Usage: python IDS.py -f <rule-filename>

System Design:

![image](https://github.com/Hsu14801/Intrusion-Detection-System/assets/117556654/9cd36be3-df3e-4e9a-b75f-6eceb4652e87)



Description:

The project aims to develop an advanced network security system that combines Intrusion Detection System (IDS) capabilities with Deep Packet Inspection (DPI). It will operate on a specific device, monitoring network traffic to and from the device it protects. The system will leverage both signature-based detection and machine learning-based anomaly detection techniques for enhanced threat detection, adaptive responses, and reduced false positives. The key features of the system include signature-based detection to identify known threats using predefined signatures or patterns, and anomaly detection to detect abnormal behavior in network traffic using machine learning algorithms. Real-time monitoring will continuously analyze network traffic for potential threats, with alerting and notification mechanisms to notify administrators of detected threats with appropriate severity levels.

Model Source: CICIDS2017 Dataset

Download Dataset here: http://205.174.165.80/CICDataset/CIC-IDS-2017/



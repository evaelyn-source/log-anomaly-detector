# log-anomaly-detector
Python-based tool to detect suspicious activity in system logs — brute force, unauthorized access, and anomalous patterns.
# 🔍 Log Anomaly Detector

A Python-based security tool that analyzes system authentication logs
to detect suspicious activity — including brute force attacks, 
unauthorized access attempts, and unusual login patterns.

## 🎯 Why I Built This
SOC analysts spend significant time manually reviewing logs.
This tool automates detection of the most common attack patterns
found in SSH auth logs.

## ⚙️ Features
- Detects brute force login attempts (configurable threshold)
- Identifies targeted usernames and source IPs
- Generates structured JSON reports
- Severity classification (HIGH / MEDIUM / LOW)

## 🚀 How to Run
git clone https://github.com/YOUR_USERNAME/log-anomaly-detector
cd log-anomaly-detector
python detector.py

## 📸 Screenshot
[add terminal screenshot here]

## 🔭 Future Improvements
- [ ] Add IP geolocation lookup
- [ ] Email alert integration
- [ ] Dashboard with matplotlib
- [ ] Support for Windows Event Logs

## 🛠 Tools & Skills Used
Python | Regex | Log Analysis | Threat Detection | JSON Reporting

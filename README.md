# log-anomaly-detector
Python-based tool to detect suspicious activity in system logs — brute force, unauthorized access, and anomalous patterns.

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
git clone https://github.com/evaelyn-source/log-anomaly-detector
cd log-anomaly-detector
python detector.py

## 📸 Screenshot
https://github.com/evaelyn-source/log-anomaly-detector/blob/main/screenshots/terminal_output.png?raw=true<img width="1152" height="648" alt="image" src="https://github.com/user-attachments/assets/a646698a-f6fe-49b5-892a-7af89d52c0a1" />


## 🔭 Future Improvements
- [ ] Add IP geolocation lookup
- [ ] Email alert integration
- [ ] Dashboard with matplotlib
- [ ] Support for Windows Event Logs

## 🛠 Tools & Skills Used
Python | Regex | Log Analysis | Threat Detection | JSON Reporting

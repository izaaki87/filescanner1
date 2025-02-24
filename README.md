# filescanner1

Ransomware Detection and Prevention Web Application
A Flask-based web application that monitors directories for suspicious file activity, detects potential ransomware behavior, and provides remediation options, including process termination and file deletion.

Features
Real-time File Monitoring – Watches a specified directory for suspicious file modifications or ransomware-related extensions.
Process Detection & Termination – Identifies high CPU usage processes that resemble ransomware behavior and attempts to terminate them.
Manual Folder Scanning – Scans an entire directory for known ransomware-related file extensions.
Log Management – Maintains an activity log of suspicious detections and allows users to clear logs.
File Upload Inspection – Detects potentially malicious files upon upload.
Web Interface – Interactive Flask-based dashboard to set monitoring directories, scan for threats, and review logs.
Technologies Used
Python, Flask
Watchdog (for real-time monitoring)
psutil (for process management)
Logging (for tracking activity)

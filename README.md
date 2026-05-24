# ML-Automation-on-Splunk-botsv1
Traced a full APT kill chain across Splunk BOTSv1 dataset, manual threat hunting meets AI/ML automation using MLTK to further mean time detection.Correlated HTTP traffic and Sysmon endpoint telemetry to reconstruct Recon-to-C2 attack sequence, identifying key IOCs including a live malware process chain and C2 callback. Deployed a DensityFunction anomaly detection model using Splunk MLTK, reducing Mean Time to Detect from hours to under 60 seconds with an automated high-severity alert.

A.  Project Overview & Objectives
This project investigates a simulated Advanced Persistent Threat (APT) network compromise using the Splunk BOTS v1 (Boss of the SOC) dataset — the gold standard dataset for practising threat hunting in a SIEM environment. The investigation follows the Lockheed Martin Cyber Kill Chain to reconstruct the full attack sequence.

Objectives
1.	Investigated a simulated network compromise using Splunk and applied the Cyber Kill Chain methodology for attack analysis and incident investigation.
2.	Utilized SPL (Search Processing Language), dashboards, and log correlation techniques to analyse security events and identify Indicators of Compromise (IOCs).
3.	Developed a basic threat detection workflow using Splunk MLTK to enhance anomaly detection and improve security monitoring visibility.

B.  Cyber Kill Chain — Attack Flow
The Lockheed Martin Cyber Kill Chain is a 7-stage framework describing how an APT attack unfolds. Stages actively investigated in this project are marked below.

1. Reconnaissance	ACTIVE — Attacker scans WayneCorp using Acunetix
2. Weaponization	Not directly observed in logs
3. Delivery	Not directly observed in logs
4. Exploitation	Web vulnerability exploited to upload malware
5. Installation	ACTIVE — 3791.exe dropped and executed via w3wp.exe
6. Command & Control	ACTIVE — Malware calls back to 23.22.63.114:3791
7. Actions on Objectives	Not fully traced in this investigation



Attack Sequence Discovered
The following attack chain was reconstructed by correlating HTTP logs with Sysmon endpoint telemetry:

1.  Attacker (40.80.148.42) scans WayneCorp server using Acunetix Vulnerability Scanner
          ↓
2.  Acunetix discovers exploitable vulnerability in the web application
          ↓
3.  Attacker uploads malicious file 3791.exe via the web exploit
          ↓
4.  IIS worker process w3wp.exe spawns cmd.exe (Sysmon Event ID 1)
          ↓
5.  cmd.exe executes 3791.exe — malware is now running on the host
          ↓
6.  3791.exe establishes C2 connection to 23.22.63.114 on Port 3791 (Sysmon Event ID 3)
   

C.  Phase I<img width="1920" height="1080" alt="Screenshot (114)" src="https://github.com/user-attachments/assets/13bbc8cf-9b00-401f-810c-22d7831b6fc3" />
 — Manual Threat Hunting
Before any automation, the attack is traced manually by following the Cyber Kill Chain, correlating logs across HTTP traffic and Sysmon endpoint telemetry.

Step 1 |  Reconnaissance — Finding the Scanner
The attacker aggressively scanned WayneCorp before exploiting it. The goal is to surface the 'loudest' IP address in HTTP traffic destined for the target server.

Key Details
-	Target server: 192.168.250.70
-	Sourcetype used: stream:http (HTTP traffic logs)
-	Technique: Aggregate request count per source IP, sort descending — the top IP is the scanner

SPL Query
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70
| stats count by src_ip
| sort - count

Query explanation:
-	index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 — filter to HTTP logs hitting the WayneCorp server only
-	| stats count by src_ip — count total requests grouped per source IP address
-	| sort - count — sort descending so the highest-count (scanner) IP appears first


<img width="1920" height="1080" alt="Screenshot (103)" src="https://github.com/user-attachments/assets/8b815120-b6b3-4376-8233-414f80ed9dfd" />

Discovery
Scanner IP identified: 40.80.148.42
The src_header field confirmed the tool used: Acunetix Vulnerability Scanner. This IP made thousands of requests — far exceeding any legitimate user.

Step 2 |  Execution — Finding the Malware
After finding a vulnerability, the attacker uploaded a malicious executable. A keyword search across all log sources reveals where the malware appears.

spl query:
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70
| search part_filename{}="*.exe*" OR uri_path="*.exe*"
| table _time, src_ip, uri_path, part_filename{}, http_method

<img width="1920" height="1080" alt="Screenshot (107)" src="https://github.com/user-attachments/assets/c7d348ab-fe96-464c-824a-ffdde8e2192d" />

Key Details
-	Sysmon Event ID 1 = Process Creation — logs what process was created, by which parent, with what command line
-	Critical parent-child chain observed: w3wp.exe -> cmd.exe -> 3791.exe
-	w3wp.exe is the IIS (Internet Information Services) web server process — it should NEVER spawn cmd.exe under normal operation

Query explanation: Simple keyword search across all indexed sourcetypes to find any reference to the malware filename. This surfaces Sysmon Event ID 1 entries showing the process creation chain.

Red Flag — Abnormal Process Chain
w3wp.exe  (IIS web server — should only serve HTTP requests)
    spawns  -->  cmd.exe  (Windows command prompt — abnormal child of web server)
                     executes  -->  3791.exe  (MALWARE)
A web server spawning a command prompt is a near-certain indicator of web shell execution or Remote Code Execution (RCE) exploitation.

Step 3  |  Command & Control — The Phone Home
Once executing, malware establishes a persistent outbound connection to the attacker's C2 (Command & Control) server. Sysmon Event ID 3 logs all network connections made by processes.

spl query:
index=botsv1 sourcetype=stream:tcp src_ip=192.168.250.70
| stats count by dest_ip, dest_port, src_ip, src_port
| sort - count

<img width="1920" height="1080" alt="Screenshot (112)" src="https://github.com/user-attachments/assets/fbfdc022-de17-4e49-a0c9-124f22d81c5a" />


Looking at the events, shows two different destination ports to 23.22.63.114

Timedest_port 03:30 → 03:49  1337
Port 1337 ("leet") is a classic hacker/attacker port — not a coincidence. 
These 3 connections happened after the initial 3791 beacon, suggesting:

The attacker may have opened a second C2 channel on port 1337
Or the malware switched ports after initial check-in

Key Details
-	Sysmon Event ID 3 = Network Connection — logs outbound connections with process name, destination IP, and port
-	Filter by process name 3791.exe to find only its outbound connections
-	Port 3791 intentionally mirrors the malware filename — a deliberate attacker signature

Discovery
C2 Server: 23.22.63.114   |   Port: 3791
The malware connected to an external IP on a non-standard port that exactly matches its own filename. This is the attacker's C2 infrastructure.


Confirmed IOCs

IOC Type	Value
Scanner IP	40.80.148.42
Scanning tool	Acunetix Vulnerability Scanner
Malware filename	3791.exe
Malicious process chain	w3wp.exe -> cmd.exe -> 3791.exe
C2 server IP	23.22.63.114
C2 port	3791

D.  Phase II — Machine Learning Automation (MLTK)
After manually identifying the attack pattern, Splunk Machine Learning Toolkit (MLTK) is used to automate future detection. This converts a manual, analyst-dependent process into an automated alert — dramatically reducing MTTD (Mean Time to Detect).

Apps to be installed on Splunk

1. Splunk AI Toolkit (MLTK)
     → Replaces old "Machine Learning Toolkit" — provides fit / apply commands

  2. Python for Scientific Computing (windows_x86_64)
     → Required backend for DensityFunction algorithm
     → Without this: Error "Failed to find Python for Scientific Computing"

Step 4  |  Training the Anomaly Detection Model

Algorithm: DensityFunction
DensityFunction models the statistical probability distribution of a numeric field from training data. Data points that fall below a probability threshold are flagged as outliers (IsOutlier=1). Think of it as teaching Splunk what 'normal Monday morning traffic' looks like so it can instantly spot aggressive scanner activity.

Strategy & Configuration
-	Baseline unit: 1-minute HTTP request count buckets (via timechart span=1m)
-	Threshold: 0.01 — any data point with probability below 1% is flagged as an outlier
-	Model name saved as: baseline_web_traffic
-	Logic: If 99% of traffic is 10-50 requests/minute, a scanner doing 5000 req/min is a massive statistical outlier

SPL Query — Model Training
index="botsv1" sourcetype="stream:http"
| timechart span=1m count
| fit DensityFunction count threshold=0.01
      into baseline_web_traffic

      <img width="1920" height="1080" alt="Screenshot (116)" src="https://github.com/user-attachments/assets/c903f1d1-7b21-4ba4-8ad9-e986873e3b6b" />


Query explanation:
-	timechart span=1m count — groups HTTP events into 1-minute buckets producing a count time series
-	fit DensityFunction count threshold=0.01 — learns the probability density of the count field from the training data, with 0.01 as the outlier threshold
-	into baseline_web_traffic — saves the trained model for later reuse on live data
  
Step 5  |  Operational Deployment

Apply the saved model to detect anomalous minutes automatically.
Any 1-minute window exceeding the trained baseline is flagged as IsOutlier=1.0
SPL QUERY — MODEL DEPLOYMENT
 index="botsv1" sourcetype="stream:http"
  | timechart span=1m count
  | apply baseline_web_traffic
  | where 'IsOutlier(count)'=1.0
  | table _time, count, 'IsOutlier(count)'
  | sort - count

  <img width="1920" height="1080" alt="Screenshot (121)" src="https://github.com/user-attachments/assets/61076d2b-b3db-46dc-aed4-9a1c53a27fd6" />

  
  - Field name must be wrapped in single quotes: 'IsOutlier(count)'
  - Filter value must be float: =1.0 (not integer =1)
  - Without quotes/float → where clause returns 0 results

Step 6 | Alert rule- Poison Ivy

ALERT NAME   : POISON IVY
WHY THE NAME : WayneCorp (Batman universe) — Poison Ivy is a Batman villain
               Also reflects the attack: looks like normal traffic but is toxic
ALERT CONFIGURATION
  Title        : POISON IVY
  Description  : DensityFunction MLTK model detected anomalous HTTP request
                 volume against WayneCorp (192.168.250.70). Possible
                 reconnaissance scanner or active attack. Investigate src_ip.
  Permissions  : Shared in App
  Alert type   : Scheduled
  Expires      : 24 hours
  Severity     : High
TRIGGER CONDITIONS
  Trigger alert when : Number of Results
  Is greater than    : 0
  Throttle           : Enabled — suppress for 5 minutes

  Why throttle 5 minutes?
    Without → alert fires every minute → floods Triggered Alerts with duplicates
    With    → fires once, suppresses for 5 min, re-fires if attack still ongoing

TRIGGER ACTION
  Action : Add to Triggered Alerts
  View   : Activity → Triggered Alerts
  HOW TO VIEW IN SPLUNK
  Activity → Triggered Alerts
  Shows: Time | Alert Name | Severity | Results | View Results link

  <img width="1920" height="1080" alt="Screenshot (123)" src="https://github.com/user-attachments/assets/2d5ed8ce-60b2-4ea2-91c6-ee97b664e04b" />

  
The saved model is applied to new or live HTTP data. Any 1-minute window where traffic volume exceeds the trained baseline will have IsOutlier=1 set automatically, which can trigger an alert in a Splunk dashboard or alert action.

MLTK Detection Workflow

Live HTTP logs ingested into Splunk
          |
          v
timechart span=1m count  -->  1-minute request count buckets
          |
          v
apply baseline_web_traffic  -->  each bucket scored vs model
          |
          v
IsOutlier=1  -->  Alert fires automatically within 60 seconds

Impact on Operations
-	Without MLTK: analyst manually reviews logs — scanner could run undetected for hours or days
-	With MLTK: every 1-minute bucket is scored automatically — alert fires within 60 seconds of anomalous traffic
-	Result: MTTD reduced from hours/days to under 1 minute

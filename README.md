# Log Analyzer & Security Dashboard

A real-time web log analyzer built with Python, Flask, and Vue.js. It monitors HTTP logs (Apache/Nginx format), detects security threats using regex rules, and visualizes data in an interactive dashboard. Includes an integrated AI Analyst powered by Ollama.

## Dashboard

### Features
- Real-time Monitoring: Tail log files and stream alerts instantly to the dashboard.
- Enriched Data: Parses User-Agents to detect Bots, Browsers, and Operating Systems.
- Interactive Dashboard: Visual charts (Severity, Top IPs, Timeline).
- Alert Details: Detailed modal view for every detected threat.
- AI Analyst: Integrated Chat interface (LLM) to analyze specific log lines or ask security questions.
- SQLite Storage: Fast, serverless database for persistent alert history.

## Prerequisites
You need Python 3 installed. Ensure you have the required libraries:

```
pip install flask ollama pyyaml user-agents
```
Note: You must have Ollama installed and running if you want to use the AI Analyst feature.

**Installation & Setup**

- Clone or Download `https://github.com/H0ll9/Log-Analyzer-system.git`:
- Install all the packages mentioned in `requirements.txt`

## Prepare your Log File:

The analyzer expects **Apache/Nginx** Combined Log Format.
Example:

`127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/user?id=1 HTTP/1.1" 200 2326 "-" "Mozilla/5.0..."`

- Place your log file (e.g., access.log) in the same directory.
- Check Rules: Open rules.yml to see the default regex patterns for SQLi, XSS, and LFI. You can add your own custom rules here.

## How to Run
### Option 1: Run with Dashboard (Server Mode)
This mode starts the Flask web server and serves the dashboard.


```
python log_analyzer_v3.py -r path/to/your/rules.yml  -f path/to/your/access.log --server
```
Wait a few seconds for the script to scan the backlog of logs.

**Open your browser and go to:**

- Dashboard: `http://localhost:5000/`
- AI Analyst: `http://localhost:5000/chat.html

### Option 2: Run in CLI Mode
Useful for piping output to other tools or viewing raw JSON in the terminal.

**Scan entire file once**

```
python log_analyzer_v3.py path/to/your/access.log
```

**Follow file (like tail -f)**
```
python log_analyzer_v3.py path/to/your/access.log --follow
```



# Screenshots
## Running log analyzer
<img width="1919" height="508" alt="Image" src="https://github.com/user-attachments/assets/96dafa9b-fe92-45d1-bd3f-a60712947aaa" />

## Main Dashboard
<img width="1919" height="1014" alt="Image" src="https://github.com/user-attachments/assets/2072f569-015f-4013-a5d0-cbf34224c7d2" />
## Visualization
<img width="1871" height="551" alt="Image" src="https://github.com/user-attachments/assets/7dfee3eb-89cc-482e-b609-614aaa2796df" />
## Filtering and Searching
<img width="1879" height="710" alt="Image" src="https://github.com/user-attachments/assets/fe6f7083-382e-432b-8895-2fc40fc3a989" />


## Alert Analysis (Modal)
Clicking any log row opens this detailed view showing IP, Payload, and Matched Pattern.

<img width="967" height="819" alt="Image" src="https://github.com/user-attachments/assets/55306a9f-02e1-417d-8573-54c56cbe0165" />

## AI Analyst
The chat interface for querying the Ollama LLM about your logs.

<img width="1919" height="1040" alt="Image" src="https://github.com/user-attachments/assets/f826fcfb-fcb8-4a2a-bde7-a0c1051e9b7b" />


## Troubleshooting

### Problem: "Clicking log records does nothing / Modal not opening"

- Cause: You might be opening the HTML file directly from your folder (file://...).
- Solution: Always access the dashboard via http://localhost:5000. Ensure the script is running with the --server flag.

### Problem: Data shows "N/A" or "Connection Lost"

- Cause: Log format mismatch. The regex parser expects strict Apache/Nginx format.
- Solution: Check your log file format. If it is different, update the HTTP_LOG_REGEX variable in the Python script.

### Problem: AI Chat returns "Failed to connect to Ollama"

- Cause: Ollama is not installed or not running.
- Solution: Ensure the Ollama application is running in the background.

## API Endpoints
If you want to integrate this with other tools, the following JSON APIs are available when the server is running:
```
GET /api/alerts - List all alerts (supports filtering by ?severity=high).
GET /api/summary - Get high-level stats (Total alerts, Bot count, Top IPs).
GET /api/distinct/<field> - Get unique values for filters.
POST /api/llm/chat - Send a message to the AI Analyst.
```

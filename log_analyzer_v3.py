#!/usr/bin/env python3
import re
import os
import sys
import time
import json
import argparse
import yaml
import logging
import threading
import sqlite3
import ollama
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Pattern, Dict, Any, Tuple
from datetime import datetime
from user_agents import parse as parse_ua
from flask import Flask, jsonify, request, send_from_directory
# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_PATH = "http_alerts.db"

# --- Data Models ---

@dataclass
class Rule:
    id: str
    name: str
    regex: str
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    whitelist: Optional[List[str]] = None

    def compile(self) -> Optional[Pattern]:
        try:
            return re.compile(self.regex, flags=re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex for rule '{self.id}': {e}")
            return None

@dataclass
class HTTPLogData:
    """Parsed data with additional security enrichment."""
    ip: str
    timestamp: str
    method: str
    url: str
    protocol: str
    status: int
    payload_size: int
    user_agent: str
    referrer: str
    raw_line: str
    # Enrichment Fields
    browser_family: str = "Unknown"
    os_family: str = "Unknown"
    is_bot: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# --- Database Layer ---

def get_db_connection():
    """Context manager for DB connections."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize SQLite database with HTTP-specific schema."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''DROP TABLE IF EXISTS alerts''') 
    
    c.execute('''
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            
            -- Alert Info
            rule_id TEXT,
            rule_name TEXT,
            severity TEXT,
            tags TEXT,
            match_text TEXT,
            
            -- HTTP Enrichment
            src_ip TEXT,
            http_method TEXT,
            http_url TEXT,
            http_status INTEGER,
            http_user_agent TEXT,
            payload_size INTEGER,
            referrer TEXT,
            
            -- Metadata
            source_file TEXT,
            lineno INTEGER,
            
            -- NEW FIELDS (Added in Dashboard update)
            browser_family TEXT,
            os_family TEXT,
            is_bot INTEGER
        )
    ''')
    
    # Indexes for fast dashboard filtering
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_http_status ON alerts(http_status)",
        "CREATE INDEX IF NOT EXISTS idx_created_at ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_rule_id ON alerts(rule_id)"
    ]
    for idx in indexes:
        c.execute(idx)
        
    conn.commit()
    conn.close()
    logger.info("Database initialized.")

def save_alert(alert: Dict[str, Any]):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO alerts 
            (created_at, rule_id, rule_name, severity, tags, match_text, 
             src_ip, http_method, http_url, http_status, http_user_agent, payload_size, referrer, 
             source_file, lineno, browser_family, os_family, is_bot)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.get("created_at"), alert.get("rule_id"), alert.get("rule_name"), 
            alert.get("severity"), json.dumps(alert.get("tags", [])), alert.get("match_text"),
            alert.get("src_ip"), alert.get("http_method"), alert.get("http_url"), 
            alert.get("http_status"), alert.get("http_user_agent"), alert.get("payload_size"), 
            alert.get("referrer"), alert.get("source_file"), alert.get("lineno"),
            alert.get("browser_family"), alert.get("os_family"), alert.get("is_bot")
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"DB Error: {e}")
    finally:
        conn.close()

# --- Core Logic: HTTP Parser & Analyzer ---

# Regex for Apache/Nginx Combined Log Format
# Example: 127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/user?id=1 HTTP/1.1" 200 2326 "-" "Mozilla/5.0..."
HTTP_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_http_log(line: str) -> Optional[HTTPLogData]:
    """Parses a raw HTTP log line and enriches User Agent."""
    match = HTTP_LOG_REGEX.match(line)
    if not match:
        return None
    
    try:
        size = match.group('size')
        payload_size = int(size) if size != '-' else 0
        ua_string = match.group('ua')

        # Parse User Agent
        ua_obj = parse_ua(ua_string)
        
        return HTTPLogData(
            ip=match.group('ip'),
            timestamp=match.group('timestamp'),
            method=match.group('method'),
            url=match.group('url'),
            protocol=match.group('protocol'),
            status=int(match.group('status')),
            payload_size=payload_size,
            user_agent=ua_string,
            referrer=match.group('referrer'),
            raw_line=line.strip(),
            browser_family=ua_obj.browser.family,
            os_family=ua_obj.os.family,
            is_bot=ua_obj.is_bot
        )
    except ValueError:
        return None

class Analyzer:
    def __init__(self, rules: List[Rule]):
        self.rules = []
        for r in rules:
            pattern = r.compile()
            if pattern:
                self.rules.append((r, pattern))
            else:
                logger.warning(f"Skipping rule {r.id} due to compilation error.")

    def analyze_line(self, line: str, lineno: Optional[int]=None, source: Optional[str]=None) -> List[Dict[str, Any]]:
        alerts = []
        
        # 1. Parse HTTP Enrichment
        http_data = parse_http_log(line)
        line_lower = line.lower()
        
        # If not HTTP log, we treat it as generic log, but with null HTTP fields
        if not http_data:
            # Optional: Skip non-HTTP lines if strictly monitoring HTTP
            # pass 
            logger.warning(f"Failed to parse log line (likely format mismatch): {line[:100]}...")
            # Create minimal fallback data
            http_data = HTTPLogData(
                ip="N/A", timestamp="N/A", method="N/A", url="-", protocol="N/A", 
                status=0, payload_size=0, user_agent="N/A", referrer="N/A", raw_line=line
            )
            return []

        # 2. Apply Security Rules
        for rule, pattern in self.rules:
            m = pattern.search(line)
            if not m:
                continue

            # Whitelist Check
            if rule.whitelist:
                skip = False
                for w in rule.whitelist:
                    if w.lower() in line_lower:
                        skip = True
                        break
                if skip:
                    continue

            match_text = m.group(0)

            # Create the Alert Object (Enriched)
            alert = {
                "created_at": datetime.utcnow().isoformat() + "Z",
                
                # Rule Info
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "tags": rule.tags, # e.g. ['sql-injection', 'owasp-top10']
                "match_text": match_text,
                
                # HTTP Enrichment
                "src_ip": http_data.ip,
                "http_method": http_data.method,
                "http_url": http_data.url,
                "http_status": http_data.status,
                "http_user_agent": http_data.user_agent,
                "payload_size": http_data.payload_size,
                "referrer": http_data.referrer,
                
                # Metadata
                "source_file": source,
                "lineno": lineno,
                "browser_family": http_data.browser_family,
                "os_family": http_data.os_family,
                "is_bot": http_data.is_bot
            }
            alerts.append(alert)
        return alerts

def load_rules(path: str) -> List[Rule]:
    if not os.path.exists(path):
        logger.error(f"Rules file not found: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML rules: {e}")
        return []

    rules = []
    if not data:
        return []

    for entry in data:
        try:
            if not entry.get("id") or not entry.get("regex"):
                continue
            rules.append(Rule(
                id=entry.get("id"),
                name=entry.get("name", entry.get("id")),
                regex=entry.get("regex"),
                severity=entry.get("severity", "medium"),
                tags=entry.get("tags", []),
                whitelist=entry.get("whitelist")
            ))
        except Exception as e:
            logger.warning(f"Failed to load rule: {e}")
            
    return rules

# --- File Watchers ---

def follow_file(path: str, analyzer: Analyzer, source: str):
    """Generator that yields lines from a file like tail -f."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        return

def scan_file(path: str, analyzer: Analyzer, source: str):
    """Scans the entire file from the beginning."""
    if not os.path.exists(path):
        logger.error(f"File not found: {path}")
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                yield i, line
    except Exception as e:
        logger.error(f"Error reading file {path}: {e}")

# --- Flask REST API ---

app = Flask(__name__)


@app.after_request
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*' # Allow from any origin
    header['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    header['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response

# Global state
analyzer: Optional[Analyzer] = None
watcher_thread: Optional[threading.Thread] = None
running = True

# --- Custom Error Handlers for Dashboard ---

@app.errorhandler(404)
def resource_not_found(e):
    return jsonify({"status": "error", "message": "Resource not found", "code": 404}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({"status": "error", "message": "Internal server error", "code": 500}), 500

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"status": "error", "message": "Bad request", "code": 400}), 400

def validate_pagination_args(args):
    """Helper to clean and validate pagination limits."""
    try:
        limit = min(int(args.get('limit', 100)), 1000) # Cap at 1000
        offset = max(int(args.get('offset', 0)), 0)
        return limit, offset
    except ValueError:
        return 100, 0 # Defaults

# --- Routes ---
# --- Serve the Frontend Dashboard ---
@app.route('/')
@app.route('/index.html')
def serve_dashboard():
    """
    Serves the HTML dashboard.
    Make sure your HTML file is named 'index.html' and is in the same folder as this script.
    """
    return send_from_directory('.', 'index.html')

# --- Serve the Chat Interface ---
@app.route('/chat.html')
def serve_chat():
    """
    Serves the Chat (AI Analyst) HTML page.
    Ensure your file is named 'chat.html'.
    """
    return send_from_directory('.', 'chat.html')


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = get_db_connection()
    c = conn.cursor()

    # 1. Base Queries
    query = "SELECT * FROM alerts WHERE 1=1"
    count_query = "SELECT COUNT(*) as total FROM alerts WHERE 1=1"
    params = []

    # 2. Filtering Logic
    if request.args.get('severity'):
        query += " AND severity = ?"
        count_query += " AND severity = ?"
        params.append(request.args.get('severity'))
    
    if request.args.get('ip'):
        query += " AND src_ip = ?"
        count_query += " AND src_ip = ?"
        params.append(request.args.get('ip'))
        
    if request.args.get('status'):
        query += " AND http_status = ?"
        count_query += " AND http_status = ?"
        params.append(int(request.args.get('status')))

    if request.args.get('method'):
        query += " AND http_method = ?"
        count_query += " AND http_method = ?"
        params.append(request.args.get('method'))

    if request.args.get('search'):
        term = f"%{request.args.get('search')}%"
        query += " AND (match_text LIKE ? OR http_url LIKE ? OR src_ip LIKE ?)"
        count_query += " AND (match_text LIKE ? OR http_url LIKE ? OR src_ip LIKE ?)"
        params.extend([term, term, term])

    # 3. Sorting & Pagination
    limit, offset = validate_pagination_args(request.args)
    
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    # 4. Execution
    try:
        c.execute(query, params)
        rows = c.fetchall()
        
        alerts = []
        for row in rows:
            alert = dict(row)
            alert['tags'] = json.loads(alert.get('tags', "[]"))
            alerts.append(alert)
        
        # Count Query
        c.execute(count_query, params[:-2]) 
        total = c.fetchone()['total']

        return jsonify({
            "status": "success", 
            "data": alerts, 
            "meta": {"total": total, "limit": limit, "offset": offset}
        })
    except Exception as e:
        logger.error(f"API Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

        
@app.route('/api/alerts/<int:alert_id>', methods=['GET'])
def get_alert_details(alert_id):
    """Get full details of a specific alert."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        alert = dict(row)
        alert['tags'] = json.loads(alert['tags'])
        return jsonify({"status": "success", "data": alert})
    
    return jsonify({"status": "error", "message": "Alert not found"}), 404

# @app.route('/api/summary', methods=['GET'])
# def get_summary():
#     """
#     High-level summary for dashboard widgets.
#     Returns: Total counts, Severity breakdown, Top 5 IPs, Top 5 Status Codes.
#     """
#     conn = get_db_connection()
#     c = conn.cursor()
    
#     summary = {}
    
#     c.execute("SELECT COUNT(*) as total FROM alerts")
#     summary['total_alerts'] = c.fetchone()['total']

#     c.execute("SELECT COUNT(*) as total FROM alerts WHERE is_bot = 1")
#     summary['total_bots'] = c.fetchone()['total']

#     # 1. Severity Counts
#     c.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
#     summary['by_severity'] = {row['severity']: row['count'] for row in c.fetchall()}
    
#     # 2. Top 5 Attacking IPs
#     c.execute("SELECT src_ip, COUNT(*) as count FROM alerts GROUP BY src_ip ORDER BY count DESC LIMIT 5")
#     summary['top_ips'] = [dict(row) for row in c.fetchall()]
    
#     # 3. Top 5 HTTP Status Codes in alerts
#     c.execute("SELECT http_status, COUNT(*) as count FROM alerts GROUP BY http_status ORDER BY count DESC LIMIT 5")
#     summary['top_status_codes'] = [dict(row) for row in c.fetchall()]
    
#     # 4. Timeline (Alerts per hour for last 24h) - Simplified
#     # SQLite datetime math is tricky, doing simple grouping by hour string
#     c.execute("""
#         SELECT substr(created_at, 1, 14) || '00:00' as hour_bucket, COUNT(*) as count 
#         FROM alerts 
#         WHERE created_at >= datetime('now', '-24 hours')
#         GROUP BY hour_bucket 
#         ORDER BY hour_bucket DESC
#     """)
#     summary['timeline'] = [{"time": r['hour_bucket'], "count": r['count']} for r in c.fetchall()]

#     conn.close()
    
#     return jsonify({"status": "success", "data": summary})

@app.route('/api/summary', methods=['GET'])
def get_summary():
    """
    High-level summary for dashboard widgets.
    Filters out 'N/A' records.
    Counts specific automated scanners based on User-Agent signatures.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    summary = {}
    
    # 1. Total Alerts (Exclude N/A)
    c.execute("SELECT COUNT(*) as total FROM alerts WHERE src_ip != 'N/A'")
    summary['total_alerts'] = c.fetchone()['total']
    
    # 2. Severity Counts (Exclude N/A)
    c.execute("SELECT severity, COUNT(*) as count FROM alerts WHERE src_ip != 'N/A' GROUP BY severity")
    summary['by_severity'] = {row['severity']: row['count'] for row in c.fetchall()}
    
    # 3. Top 5 Attacking IPs (Exclude N/A)
    c.execute("SELECT src_ip, COUNT(*) as count FROM alerts WHERE src_ip != 'N/A' GROUP BY src_ip ORDER BY count DESC LIMIT 5")
    summary['top_ips'] = [dict(row) for row in c.fetchall()]
    
    # 4. Top 5 HTTP Status Codes (Exclude Status 0)
    c.execute("SELECT http_status, COUNT(*) as count FROM alerts WHERE http_status != 0 GROUP BY http_status ORDER BY count DESC LIMIT 5")
    summary['top_status_codes'] = [dict(row) for row in c.fetchall()]
    
    # 5. Automated Scanners Count (NEW LOGIC)
    # Common User-Agents used by attack tools
    scanner_keywords = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'wpscan', 'xsser', 
        'hydra', 'medusa', 'python-requests', 'curl', 'wget', 
        'gobuster', 'dirbuster', 'zmap', 'zgrab', 'zap', 'burp', 
        'libwww-perl', 'lwp-simple', 'java', 'perl'
    ]
    
    # Build SQL condition: (http_user_agent LIKE '%sqlmap%' OR http_user_agent LIKE '%nikto%' ...)
    # We also check for empty User Agents ('-') as scanners often strip them
    scanner_conditions = ' OR '.join([f"http_user_agent LIKE '%{kw}%'" for kw in scanner_keywords])
    scanner_query = f"""
        SELECT COUNT(*) as total 
        FROM alerts 
        WHERE src_ip != 'N/A' 
        AND ({scanner_conditions} OR http_user_agent = '-' OR http_user_agent = '')
    """
    c.execute(scanner_query)
    summary['total_bots'] = c.fetchone()['total']

    # 6. Timeline (Exclude N/A)
    c.execute("""
        SELECT substr(created_at, 1, 14) || '00:00' as hour_bucket, COUNT(*) as count 
        FROM alerts 
        WHERE created_at >= datetime('now', '-24 hours') AND src_ip != 'N/A'
        GROUP BY hour_bucket 
        ORDER BY hour_bucket DESC
    """)
    summary['timeline'] = [{"time": r['hour_bucket'], "count": r['count']} for r in c.fetchall()]

    conn.close()
    
    return jsonify({"status": "success", "data": summary})

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """List currently loaded detection rules."""
    if not analyzer:
        return jsonify({"status": "error", "message": "Analyzer not initialized"}), 500
    
    rules_data = []
    for r, _ in analyzer.rules:
        rules_data.append(asdict(r))
    return jsonify({"status": "success", "data": rules_data})

@app.route('/api/distinct/<string:field>', methods=['GET'])
def get_distinct_values(field):
    """Returns distinct values for a field, sorted alphabetically."""
    allowed_fields = ['severity', 'http_method', 'http_status', 'src_ip', 'rule_id']
    if field not in allowed_fields:
        return jsonify({"status": "error", "message": "Invalid field"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    try:
        # Limit to top 50 distinct values, sorted
        query = f"SELECT DISTINCT {field} FROM alerts WHERE {field} IS NOT NULL AND {field} != '' ORDER BY {field} ASC LIMIT 50"
        c.execute(query)
        values = [row[0] for row in c.fetchall()]
        return jsonify({"status": "success", "data": values})
    except Exception as e:
        logger.error(f"Error fetching distinct values: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

# --- Ollama LLM Integration ---

OLLAMA_MODEL = "qwen2.5-coder:7b" 

SYSTEM_PROMPT = """
You are an expert Cyber Security Analyst and SIEM Specialist.
Your role is to analyze web server logs, detect security threats (SQLi, XSS, LFI, DDoS), and suggest mitigation strategies.
Be concise, professional, and technical.
If a log line is provided, explain the attack vector, severity, and the matched payload.
If asked for suggestions, provide actionable steps to secure the server or improve the ruleset.
Do not answer non-security questions. If the input is unrelated to logs or security, politely decline.
"""

@app.route('/api/llm/chat', methods=['POST'])
def chat_with_llm():
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({"status": "error", "message": "Message is empty"}), 400

    try:
        # Call Ollama
        response = ollama.chat(model=OLLAMA_MODEL, messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': user_message}
        ])
        
        reply = response['message']['content']
        return jsonify({"status": "success", "reply": reply})
        
    except Exception as e:
        logger.error(f"Ollama Error: {e}")
        return jsonify({"status": "error", "message": "Failed to connect to Ollama model."}), 500


# --- Background Worker ---
def background_watcher(file_path, source_name):
    global running
    logger.info(f"Background watcher started for {file_path}")
    
    # Initial scan
    logger.info("Performing initial scan of backlog...")
    for lineno, line in scan_file(file_path, analyzer, source_name):
        alerts = analyzer.analyze_line(line, lineno, source_name)
        for a in alerts:
            save_alert(a)
    logger.info("Initial scan complete. Streaming updates...")

    # Follow file
    for line in follow_file(file_path, analyzer, source_name):
        if not running:
            break
        alerts = analyzer.analyze_line(line, lineno=None, source=source_name)
        for a in alerts:
            save_alert(a)

# --- Main Entry Point ---

def main():
    
    global analyzer, running

    parser = argparse.ArgumentParser(description="HTTP Log Analyzer with REST API.")
    parser.add_argument("file", help="HTTP Log file to analyze (Apache/Nginx format).")
    parser.add_argument("-r", "--rules", default="rules.yml", help="YAML rules file path.")
    parser.add_argument("--server", action="store_true", help="Start Flask API server.")
    parser.add_argument("--port", type=int, default=5000, help="Port for Flask server.")
    parser.add_argument("-f", "--follow", action="store_true", help="Follow file (CLI mode only).")
    
    args = parser.parse_args()

    # Load Rules
    rules = load_rules(args.rules)
    if not rules:
        logger.warning("No valid rules loaded. Running in detection-free mode.")
    
    analyzer = Analyzer(rules)
    logger.info(f"Loaded {len(rules)} rules.")

    if args.server:
        init_db()
        
        source_name = os.path.basename(args.file)
        
        # Start watcher in daemon thread
        t = threading.Thread(target=background_watcher, args=(args.file, source_name))
        t.daemon = True
        t.start()
        
        logger.info(f"Starting API Dashboard on port {args.port}...")
        logger.info("Try: curl http://localhost:5000/api/summary")
        try:
            app.run(host='0.0.0.0', port=args.port, debug=False, use_reloader=False)
        except KeyboardInterrupt:
            running = False
            logger.info("Shutting down...")
        return

    # CLI Mode
    source_name = os.path.basename(args.file)
    
    if args.follow:
        logger.info(f"Following {args.file}...")
        try:
            for line in follow_file(args.file, analyzer, source_name):
                alerts = analyzer.analyze_line(line, lineno=None, source=source_name)
                for a in alerts:
                    # Print enriched JSON to stdout
                    print(json.dumps(a))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            pass
    else:
        for lineno, line in scan_file(args.file, analyzer, source_name):
            alerts = analyzer.analyze_line(line, lineno=lineno, source=source_name)
            for a in alerts:
                print(json.dumps(a))
    
if __name__ == "__main__":
    main()
import random
from datetime import datetime, timedelta

# --- CONFIGURATION ---

# User Agents (Categorized)
bot_agents = [
    "sqlmap/1.4.9#stable",
    "curl/7.68.0", 
    "Nmap Scripting Engine",
    "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34"
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

# IPs (Categorized to make logs look realistic)
attacker_ips = ["10.0.0.23", "203.0.113.5"]      # IPs used for SQLi/XSS
bot_ips = ["10.0.0.23", "198.51.100.23", "103.21.244.0"] # IPs used for scanning
normal_ips = ["192.168.1.101", "185.220.101.45"]  # Normal users

# Paths (Categorized)
malicious_paths = [
    "/.env",                               # Sensitive file scan
    "/phpmyadmin",                          # Admin panel scan
    "/admin",                                # Admin panel
    "/index.php?id=1' OR '1'='1",          # SQL Injection
    "/search?q=<script>alert(1)</script>"   # XSS
]

benign_paths = [
    "/", "/login", "/dashboard", "/images/logo.png", "/assets/style.css"
]

# --- HELPER FUNCTIONS ---

def create_log_line(ip, timestamp, method, path, status, size, user_agent):
    # Format: 54.175.105.120 - - [07/Jun/2025:20:31:36 -0700] "GET / HTTP/1.1" 200 18202 "-" "UserAgent"
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'

def get_timestamp():
    # Generate a random time in the last 24 hours
    time_offset = timedelta(seconds=random.randint(0, 86400))
    return (datetime.now() - time_offset).strftime("%d/%b/%Y:%H:%M:%S -0700")

# --- GENERATION LOGIC ---

log_lines = []

# We generate 500 lines
for _ in range(500):
    
    # Decide the type of traffic session
    # 30% Bot/Scanner, 20% Attacker, 50% Normal User
    traffic_type = random.choices(['bot', 'attacker', 'normal'], weights=[0.3, 0.2, 0.5])[0]
    
    if traffic_type == 'bot':
        # SCANNER BEHAVIOR: 
        # Bot IP + Bot UA + Malicious/Scanning Path
        ip = random.choice(bot_ips)
        ua = random.choice(bot_agents)
        path = random.choice(malicious_paths)
        method = "GET"
        # Scanners often get 404 or 500
        status = random.choice([404, 403, 500])
        size = random.randint(500, 5000)

    elif traffic_type == 'attacker':
        # ATTACKER BEHAVIOR:
        # Random IP + Browser (to blend in) + Malicious Path
        ip = random.choice(attacker_ips)
        ua = random.choice(user_agents) 
        path = random.choice(malicious_paths)
        method = random.choice(["GET", "POST"])
        # Attacks often get blocked (403) or cause errors (500) or succeed (200)
        status = random.choice([403, 500, 200, 404])
        size = random.randint(100, 20000)

    else:
        # NORMAL USER BEHAVIOR:
        # Normal IP + Browser UA + Benign Path
        ip = random.choice(normal_ips)
        ua = random.choice(user_agents)
        path = random.choice(benign_paths)
        method = random.choice(["GET", "POST"])
        # Normal traffic usually 200 or 301
        status = random.choice([200, 301, 304])
        size = random.randint(200, 15000)

    timestamp = get_timestamp()
    
    log_lines.append(create_log_line(ip, timestamp, method, path, status, size, ua))

# --- OUTPUT ---

output_filename = "generated_access_log.txt"
with open(output_filename, "w") as f:
    f.write("\n".join(log_lines))

print(f"Generated {len(log_lines)} log lines into '{output_filename}'")
print("These logs correlate User Agents with Paths to trigger your rules.yml effectively.")
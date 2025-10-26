# Practical, extendable Log Analyzer that detects attack patterns using (1) default rule-set and (2) user-supplied regex rules

Scan an existing file:

```
python3 log_analyzer.py /var/log/nginx/access.log -r rules.yml
```

Follow a file in real time:

```
python3 log_analyzer.py /var/log/nginx/access.log -r rules.yml --follow
```


Pipe from another tool:
```
tail -n 1000 /var/log/nginx/access.log | python3 log_analyzer.py - -r rules.yml

```

6) Tuning, reducing false positives, and hardening

Context-aware parsing: If you parse structured logs (JSON logs, combined log format), extract fields (URL, headers, UA, referrer) and run regex only on relevant fields — reduces noise.

Whitelist: Add whitelist entries per rule or IP-based whitelists to avoid scanning internal scanners.

Rate-limiting/de-dupe: Aggregate repeated matches from the same IP or same rule within a time window before alerting.

Scoring: Give weights to rules and alert on score threshold to reduce low-confidence alerts.

Correlation: Combine multiple low-confidence alarms into a high-confidence incident if they occur in a time window.

Enrichment: Add GeoIP, ASN, threat-intel feeds, and user agent parsing to boost context.

Test rules: Run the rules over historical logs and sample good traffic to tune regexes. Keep a "allowlist" of safe-but-weird requests.

Performance: Pre-compile regex, avoid catastrophic backtracking (use non-greedy patterns or atomic groups), and consider using regex package if you need advanced features.

Production scaling: For large volumes, push logs into Kafka, use streaming processors (Flink, Spark, Beam), or write a native plugin for Filebeat/Logstash.




7) Next steps & optional improvements

If you want I can:

Convert the script into a small service with a REST API that accepts log lines and returns matches.

Add a web UI (Streamlit or small React app) showing live alerts and trends.

Add correlation and alert throttling (grouping).

Add Elastic/Kibana output or a webhook integration (Slack, PagerDuty).

Provide tuned rules for a specific app (e.g., WordPress, Drupal, Apache mod_security translation).

## 2. Live simulation demo (real-time attack detection)

`python3 log_analyzer.py sample.log -r rules.yml --follow`

## Step 2. In another terminal window, append fake log entries

```
echo '192.168.1.11 - - [26/Oct/2025:12:10:00 +0000] "GET /search?q=UNION SELECT user,password FROM admin HTTP/1.1" 200 512' >> sample.log

echo '192.168.1.12 - - [26/Oct/2025:12:10:01 +0000] "GET /index.php?page=../../etc/passwd HTTP/1.1" 200 612' >> sample.log

echo '192.168.1.13 - - [26/Oct/2025:12:10:02 +0000] "GET /?name=<script>alert(1)</script> HTTP/1.1" 200 400' >> sample.log

```


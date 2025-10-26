#!/usr/bin/env python3
"""
log_analyzer.py
Simple streaming log analyzer using YAML-defined regex rules.
Outputs JSON lines for matches.
"""

from __future__ import annotations
import re
import sys
import time
import json
import argparse
from dataclasses import dataclass, asdict
from typing import List, Optional, Pattern
import yaml
import os
from datetime import datetime

@dataclass
class Rule:
    id: str
    name: str
    regex: str
    severity: str = "medium"
    tags: List[str] = None
    description: str = ""
    whitelist: Optional[List[str]] = None

    def compile(self) -> Pattern:
        # compile with IGNORECASE and DOTALL so patterns are expressive
        return re.compile(self.regex, flags=re.IGNORECASE | re.DOTALL)

class Analyzer:
    def __init__(self, rules: List[Rule], max_context: int = 200):
        self.rules = [(r, r.compile()) for r in rules]
        self.max_context = max_context

    def analyze_line(self, line: str, lineno: Optional[int]=None, source: Optional[str]=None):
        matches = []
        for rule, pattern in self.rules:
            m = pattern.search(line)
            if not m:
                continue
            # whitelist check: if any whitelist substring present, skip
            if rule.whitelist:
                skip = False
                for w in rule.whitelist:
                    if w in line:
                        skip = True
                        break
                if skip:
                    continue
            # build alert
            match_text = m.group(0)
            # clamp context
            context = line.strip()
            if len(context) > self.max_context:
                context = context[:self.max_context] + "..."
            alert = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": source,
                "lineno": lineno,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "tags": rule.tags or [],
                "match": match_text,
                "line": context
            }
            matches.append(alert)
        return matches

def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    rules = []
    for entry in data:
        rules.append(Rule(
            id=entry.get("id"),
            name=entry.get("name", entry.get("id")),
            regex=entry.get("regex"),
            severity=entry.get("severity", "medium"),
            tags=entry.get("tags", []),
            description=entry.get("description", ""),
            whitelist=entry.get("whitelist", None)
        ))
    return rules

def follow_file(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        # go to end
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def scan_file(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            yield i, line

def main():
    parser = argparse.ArgumentParser(description="Simple log analyzer with regex rules (YAML).")
    parser.add_argument("file", help="Log file to analyze. Use '-' for stdin.")
    parser.add_argument("-r", "--rules", default="rules.yml", help="YAML rules file path.")
    parser.add_argument("-f", "--follow", action="store_true", help="Follow file (like tail -f).")
    parser.add_argument("--json", action="store_true", help="Output JSON lines (default true if not set).")
    parser.add_argument("--quiet", action="store_true", help="Only output matches, no extra info.")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    analyzer = Analyzer(rules)

    if args.file == "-":
        # read stdin stream
        for lineno, line in enumerate(sys.stdin, start=1):
            alerts = analyzer.analyze_line(line, lineno=lineno, source="stdin")
            for a in alerts:
                sys.stdout.write(json.dumps(a) + "\n")
                sys.stdout.flush()
        return

    if args.follow:
        for line in follow_file(args.file):
            alerts = analyzer.analyze_line(line, lineno=None, source=args.file)
            for a in alerts:
                print(json.dumps(a))
    else:
        for lineno, line in scan_file(args.file):
            alerts = analyzer.analyze_line(line, lineno=lineno, source=args.file)
            for a in alerts:
                print(json.dumps(a))

if __name__ == "__main__":
    main()


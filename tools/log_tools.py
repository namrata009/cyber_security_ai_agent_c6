import json
import os
from typing import Optional
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import re

load_dotenv()

@tool
def analyze_logs(log_file: str = "sample_logs/suspicious_logs.json") -> str:
    """Analyze JSON security logs for anomalies and threats"""
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            return "⚠️ Log file not found - create sample_logs/suspicious_logs.json"
        
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        anomalies = []
        
        for log in logs[:10]:  # Analyze top 10
            rpm = log.get('requests_per_minute', 0)
            message = log.get('message', '')
            
            if rpm > 1000 or 'fail' in message.lower():
                anomalies.append({
                    'ip': log.get('ip', 'unknown'),
                    'message': message,
                    'rpm': rpm,
                    'threat': detect_patterns(message)
                })
        
        severity = "CRITICAL" if len(anomalies) > 3 else "HIGH" if anomalies else "CLEAR"
        summary = f"📊 {len(logs)} logs | 🚨 {len(anomalies)} anomalies | Severity: {severity}"
        
        if anomalies:
            summary += f"\nTop threats:\n" + "\n".join([f"- {a['ip']}: {a['threat']}" for a in anomalies])
        
        return summary
    except Exception as e:
        return f"❌ Analysis error: {str(e)}"

def detect_patterns(log_message: str) -> str:
    """Detect specific attack patterns in log messages"""
    message = str(log_message).lower()
    
    patterns = {
        'Brute Force': ['failed login', 'authentication failure', 'invalid credentials'],
        'SQL Injection': ['or 1=1', 'drop table', 'union select', "'; --", 'script'],
        'XSS': ['<script', 'javascript:', 'onerror=', 'alert('],
        'DDoS/Command Injection': ['traffic spike', 'syn flood', 'rm -rf', '| bash'],
        'Privilege Escalation': ['sudo', 'root access', 'su root']
    }
    
    threats = []
    for threat, keywords in patterns.items():
        if any(re.search(re.escape(kw), message) for kw in keywords):
            threats.append(threat)
    
    return ', '.join(threats) if threats else 'Clean - No known patterns'

detect_patterns_tool = tool(detect_patterns)

@tool
def threat_score(log_entry: dict) -> str:
    """Calculate threat score for single log entry"""
    rpm = log_entry.get('requests_per_minute', 0)
    message = str(log_entry.get('message', '')).lower()
    
    score = 0
    if rpm > 2000: score += 40
    elif rpm > 1000: score += 20
    if 'fail' in message: score += 30
    if 'sql' in message or 'drop' in message: score += 50
    
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
    
    return f"Threat Score: {score}/100 | Level: {level}"

# LangChain Agent Tools Ready!
if __name__ == "__main__":
    print("🛠️ LangChain Tools Ready:")
    print(analyze_logs())
    print(detect_patterns("failed login OR 1=1"))
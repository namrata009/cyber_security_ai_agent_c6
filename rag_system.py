import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
import re

load_dotenv()

class SecurityRAG:
    def __init__(self):
        """Pure OpenAI RAG - No ChromaDB needed"""
        api_key = os.getenv("OPENAI_API_KEY")
        self.mock_mode = False

        if not api_key or 'your-key-here' in api_key:
            print("⚠️ OpenAI key missing or placeholder; running in mock mode")
            self.llm = None
            self.mock_mode = True
        else:
            print(f"✅ RAG ready: {api_key[:10]}...")
            self.llm = ChatOpenAI(
                model="gpt-4o-mini", 
                temperature=0,
                openai_api_key=api_key
            )
        
        # FIXED: Define knowledge_base HERE
        self.knowledge_base = """
NIST Framework: Identify, Protect, Detect, Respond, Recover
Attack Patterns:
- Brute Force: 'failed login', requests_per_minute > 1000
- SQL Injection: ' OR 1=1', DROP TABLE, UNION SELECT  
- XSS: <script>, javascript:
- DDoS: requests_per_minute > 2000
- Privilege Escalation: sudo, root access

Response Playbook:
1. Isolate: Block IP address immediately
2. Analyze: Check full logs for patterns  
3. Remediate: Patch, update firewall rules
4. Monitor: Watch for repeat attacks
"""
    
    def analyze_log_entry(self, log_entry: dict) -> dict:
        """Analyze single log"""
        message = str(log_entry.get('message', '')).lower()
        rpm = log_entry.get('requests_per_minute', 0)
        
        threats = []
        severity = "LOW"
        
        if 'failed login' in message or rpm > 1000:
            threats.append("Brute Force")
            severity = "HIGH" if rpm > 1000 else "MEDIUM"
        
        if any(x in message for x in ['or 1=1', 'drop table', 'union select']):
            threats.append("SQL Injection")
            severity = "CRITICAL"
        
        if 'sudo' in message or 'root' in str(log_entry.get('user', '')):
            threats.append("Privilege Escalation")
            severity = "HIGH"
        
        if rpm > 2000:
            threats.append("DDoS")
            severity = "CRITICAL"
        
        return {
            "threats": threats,
            "severity": severity,
            "rpm": rpm,
            "recommendation": self.get_recommendation(severity, threats)
        }
    
    def get_recommendation(self, severity: str, threats: list) -> str:
        """Remediation steps"""
        recs = {
            "CRITICAL": "🚨 IMMEDIATE: Block IP, isolate system, call incident response",
            "HIGH": "🔴 URGENT: Block IP, enable rate limiting, audit logs", 
            "MEDIUM": "🟡 MONITOR: Add to watchlist, check patterns",
            "LOW": "✅ NORMAL: Continue monitoring"
        }
        return recs.get(severity, "Monitor")
    
    def query(self, question: str, logs=None) -> str:
        """Main query method - FIXED!"""
        if self.llm is None:
            return "⚠️ OpenAI API key required in .env"
        
        # Use self.knowledge_base (FIXED)
        context = self.knowledge_base
        
        if logs:
            analysis = []
            for log in logs[:3]:
                result = self.analyze_log_entry(log)
                analysis.append(f"Log: {log.get('message', 'N/A')} → {result['severity']} ({', '.join(result['threats'])})")
            context += f"\nRecent Logs:\n" + "\n".join(analysis)
        
        prompt = f"""
{self.knowledge_base}  # ← FIXED: Now uses self.knowledge_base

Context: {context}

Question: {question}

Respond with:
1. Severity (CRITICAL/HIGH/MEDIUM/LOW)
2. Detected threats  
3. 3-step remediation plan
"""
        
        if self.llm is None:
            return self._mock_response(question)

        try:
            response = self.llm.invoke(prompt)
            return f"🔍 AI Security Analysis:\n```\n{response.content}\n```"
        except Exception:
            return self._mock_response(question)

    def _mock_response(self, question: str) -> str:
        q = question.lower()
        threats = []
        severity = "LOW"

        if any(x in q for x in ["failed login", "login", "unauthorized", "anomaly"]):
            threats.append("Brute Force")
            severity = "HIGH"
        if any(x in q for x in ["sql injection", "or 1=1", "drop table", "union select"]):
            threats.append("SQL Injection")
            severity = "CRITICAL"
        if any(x in q for x in ["ddos", "requests/min", "traffic spike"]):
            threats.append("DDoS")
            severity = "CRITICAL"
        if any(x in q for x in ["sudo", "root", "privilege escalation"]):
            threats.append("Privilege Escalation")
            severity = "HIGH"
        if not threats:
            threats.append("Unknown or low-risk anomaly")
            severity = "MEDIUM"

        recommendation = self.get_recommendation(severity, threats)
        return (
            "🔍 Mock AI Security Analysis:\n```"
            f"\nSeverity: {severity}\n"
            f"Detected threats: {', '.join(threats)}\n"
            f"Remediation: {recommendation}\n```"
        )

# Test
if __name__ == "__main__":
    rag = SecurityRAG()
    print(rag.query("suspicious logins from same IP"))
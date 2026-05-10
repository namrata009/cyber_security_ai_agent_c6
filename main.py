import os
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
from rich.table import Table
import pyfiglet
from datetime import datetime
import json
from rag_system import SecurityRAG
from supervisor import Supervisor

console = Console()

class CyberSecurityAI:
    def __init__(self):
        self.rag = SecurityRAG()
        self.supervisor = Supervisor()
        self.console = Console()
    
    def create_sample_logs(self):
        """Generate sample suspicious logs for testing"""
        sample_logs = {
            "logs": [
                {"timestamp": "2026-05-09T17:00:00", "user": "admin", "ip": "185.220.101.5", "message": "failed login attempt", "requests_per_minute": 1500},
                {"timestamp": "2026-05-09T17:01:00", "user": "root", "ip": "103.75.117.23", "message": "sudo privilege escalation detected", "user_agent": "evil-bot-crawler"},
                {"timestamp": "2026-05-09T17:02:00", "user": "www-data", "ip": "185.220.101.5", "message": "suspicious SQL query", "requests_per_minute": 2500}
            ]
        }
        os.makedirs("sample_logs", exist_ok=True)
        with open("sample_logs/suspicious_logs.json", "w") as f:
            json.dump(sample_logs, f)
    
    def run_demo(self):
        self.create_sample_logs()
        
        banner = pyfiglet.figlet_format("CyberSec AI", font="small")
        rprint(Panel(banner, title="🚀 Cyber Security AI Agent System", border_style="bold green"))
        
        # Simulate real-time monitoring
        alerts = [
            {"id": 1, "type": "LOG_ANOMALY", "description": "Multiple failed logins from suspicious IP 185.220.101.5"},
            {"id": 2, "type": "CVE_ALERT", "description": "CVE-2021-44228 (Log4Shell) detected in application logs"},
            {"id": 3, "type": "TRAFFIC_SPIKE", "description": "2500 requests/min from single IP - potential DDoS"}
        ]
        
        table = Table(title="Real-time Security Alerts")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Status", style="green")
        
        for alert in alerts:
            # RAG-enhanced analysis
            rag_response = self.rag.query(alert['description'])
            analysis = self.supervisor.route_to_agent(alert['description'])
            
            table.add_row(
                str(alert['id']),
                alert['type'],
                alert['description'][:50] + "...",
                f"Analyzed by {analysis}"
            )
            
            # Show RAG context
            rprint(f"\n🔍 RAG Analysis for {alert['id']}:")
            rprint(Panel(rag_response[:300] + "...", title=f"Alert {alert['id']}", border_style="blue"))
        
        table.add_row("---", "---", "---", "🚨 SUPERVISOR ACTIVE")
        self.console.print(table)

if __name__ == "__main__":
    ai = CyberSecurityAI()
    ai.run_demo()
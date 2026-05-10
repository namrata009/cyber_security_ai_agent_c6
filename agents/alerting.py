import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import requests
from typing import Dict
import os
from dotenv import load_dotenv

load_dotenv()

class AlertingSystem:
    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK")
        self.email_config = {
            "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            "smtp_port": int(os.getenv("SMTP_PORT", 587)),
            "email": os.getenv("ALERT_EMAIL"),
            "password": os.getenv("EMAIL_PASSWORD")
        }
    
    def send_slack_alert(self, alert: Dict):
        """Send Slack alert for critical issues"""
        if not self.slack_webhook:
            print("⚠️ Slack webhook not configured")
            return
        
        severity_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡"}
        emoji = severity_emoji.get(alert.get('severity', 'MEDIUM'), "ℹ️")
        
        payload = {
            "text": f"{emoji} *{alert['type']}*\n{alert['description']}\n<@{alert.get('user', 'U123')}>",
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"{emoji} *{alert['type']}*\n{alert['description']}"}
            }]
        }
        
        requests.post(self.slack_webhook, json=payload)
        print(f"✅ Slack alert sent: {alert['type']}")
    
    def send_email_alert(self, alert: Dict, to_email: str):
        """Send email alert"""
        msg = MimeMultipart()
        msg['From'] = self.email_config['email']
        msg['To'] = to_email
        msg['Subject'] = f"🚨 Security Alert: {alert['type']}"
        
        body = f"""
        Security Alert Detected:
        Type: {alert['type']}
        Severity: {alert['severity']}
        Description: {alert['description']}
        Time: {alert.get('timestamp', 'Now')}
        """
        msg.attach(MimeText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['email'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            print(f"✅ Email alert sent to {to_email}")
        except Exception as e:
            print(f"❌ Email error: {e}")

# Test alerting
if __name__ == "__main__":
    alerts = AlertingSystem()
    test_alert = {
        "type": "DOCKER_VULN", 
        "severity": "CRITICAL",
        "description": "nginx:latest has 5 critical CVEs"
    }
    alerts.send_slack_alert(test_alert)
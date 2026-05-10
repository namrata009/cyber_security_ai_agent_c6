import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

class AlertingSystem:
    def __init__(self):
        """Fixed constructor - no clients argument needed"""
        self.slack_webhook = os.getenv("SLACK_WEBHOOK")
        self.email_config = {
            "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            "smtp_port": int(os.getenv("SMTP_PORT", 587)),
            "email": os.getenv("ALERT_EMAIL"),
            "password": os.getenv("EMAIL_PASSWORD")
        }
        print("✅ AlertingSystem initialized")
    
    def send_slack_alert(self, alert: dict):
        """Send Slack alert for critical issues"""
        if not self.slack_webhook:
            print("⚠️ No Slack webhook - skipping")
            return False
        
        severity_emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "INFO": "ℹ️"}
        emoji = severity_emoji.get(alert.get('severity', 'INFO'), "ℹ️")
        
        payload = {
            "text": f"{emoji} *{alert['type']}*\n{alert['description']}\nTime: {datetime.now().strftime('%H:%M:%S')}",
        }
        
        try:
            response = requests.post(self.slack_webhook, json=payload, timeout=10)
            if response.status_code == 200:
                print(f"✅ Slack alert sent: {alert['type']}")
                return True
            else:
                print(f"❌ Slack error: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Slack error: {str(e)}")
            return False
    
    def send_email_alert(self, alert: dict, to_email: str = None):
        """Send email alert"""
        if not self.email_config['email'] or not self.email_config['password']:
            print("⚠️ Email config missing - skipping")
            return False
        
        to_email = to_email or self.email_config['email']
        
        msg = MIMEMultipart()
        msg['From'] = self.email_config['email']
        msg['To'] = to_email
        msg['Subject'] = f"🚨 Security Alert: {alert['type']}"
        
        body = f"""
🚨 SECURITY ALERT 🚨

Type: {alert['type']}
Severity: {alert['severity']}
Description: {alert['description']}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Anomalies: {alert.get('anomaly_count', 0)}

---
CyberSec AI Agent
        """
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(self.email_config['email'], self.email_config['password'])
            text = msg.as_string()
            server.sendmail(self.email_config['email'], to_email, text)
            server.quit()
            print(f"✅ Email sent to {to_email}")
            return True
        except Exception as e:
            print(f"❌ Email error: {type(e).__name__}: {str(e)}")
            return False
    
    def test_alert(self):
        """Test alerting system"""
        test_alert = {
            "type": "TEST_ALERT",
            "severity": "INFO",
            "description": "Alerting system test successful!"
        }
        slack_ok = self.send_slack_alert(test_alert)
        email_ok = self.send_email_alert(test_alert)
        return slack_ok or email_ok

# Test
if __name__ == "__main__":
    alerts = AlertingSystem()
    alerts.test_alert()
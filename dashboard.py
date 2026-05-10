import streamlit as st
import pandas as pd
import plotly.express as px
import json
from datetime import datetime, timedelta
from tools.log_tools import analyze_logs, detect_patterns, threat_score
import time

st.set_page_config(page_title="CyberSec AI Dashboard", layout="wide", initial_sidebar_state="expanded")

# Custom CSS
st.markdown("""
<style>
.main-header {font-size: 3rem; color: #1f77b4; text-align: center;}
.metric-card {background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 1rem; border-radius: 10px;}
.alert-high {background: linear-gradient(135deg, #ff4444, #cc0000); color: white; padding: 15px; border-radius: 8px;}
.alert-crit {background: linear-gradient(135deg, #ff1744, #d50000); color: white; padding: 15px; border-radius: 8px;}
</style>
""", unsafe_allow_html=True)

class CyberSecDashboard:
    def __init__(self):
        """Safe initialization - NO Docker dependencies"""
        try:
            from alerting import AlertingSystem
            self.alerts_system = AlertingSystem()
            print("✅ Alerting system loaded")
        except:
            print("⚠️ Alerting disabled")
            self.alerts_system = None
        self.uploaded_logs = None
    
    def parse_uploaded_logs(self, uploaded_file):
        """Parse JSON logs from upload"""
        try:
            data = json.load(uploaded_file)
            logs = data if isinstance(data, list) else data.get('logs', [])
            df = pd.DataFrame(logs)
            
            # Smart analysis
            if 'requests_per_minute' not in df:
                df['requests_per_minute'] = 0
            df['anomaly_score'] = df['requests_per_minute'].apply(lambda x: 1 if x > 1000 else 0)

            df['message'] = df['message'].fillna('').astype(str) if 'message' in df else ''
            df['threat_type'] = df['message'].apply(detect_patterns)
            df['timestamp'] = pd.to_datetime(df['timestamp'] if 'timestamp' in df else datetime.now(), errors='coerce')
            
            self.uploaded_logs = df
            return df
        except Exception as e:
            st.error(f"❌ JSON parse error: {str(e)}")
            return None
    
    def generate_report(self, df):
        """Generate security metrics"""
        anomalies = df[df['anomaly_score'] == 1]
        return {
            'total': len(df),
            'anomalies': len(anomalies),
            'critical_ips': len(df[df['anomaly_score'] == 1]['ip'].unique()) if 'ip' in df else 0,
            'top_threat': df['threat_type'].value_counts().index[0] if len(df) > 0 else 'None'
        }
    
    def run(self):
        st.markdown('<h1 class="main-header">🛡️ CyberSec AI Log Analyzer</h1>', unsafe_allow_html=True)
        
        # === JSON UPLOAD ===
        st.header("📁 Upload Log File (JSON)")
        col1, col2 = st.columns([3, 1])
        
        with col1:
            uploaded_file = st.file_uploader("Choose JSON file", type=['json'])
        
        with col2:
            if st.button("📋 Load Sample Logs"):
                sample_logs = [
                    {"timestamp": "2026-05-10T01:00:00Z", "user": "admin", "ip": "185.220.101.5", "message": "failed login", "requests_per_minute": 1500},
                    {"timestamp": "2026-05-10T01:01:00Z", "user": "root", "ip": "103.75.117.23", "message": "SQL injection", "requests_per_minute": 2500},
                    {"timestamp": "2026-05-10T01:02:00Z", "user": "www-data", "ip": "185.220.101.5", "message": "DDoS detected", "requests_per_minute": 3500}
                ]
                df = pd.DataFrame(sample_logs)
                df['anomaly_score'] = [1, 1, 1]
                df['threat_type'] = ['Brute Force', 'SQL Injection', 'DDoS']
                st.session_state['logs_df'] = df
                st.success("✅ Sample logs loaded!")
        
        if uploaded_file:
            df = self.parse_uploaded_logs(uploaded_file)
            if df is not None:
                st.session_state['logs_df'] = df
                st.success(f"✅ Analyzed {len(df)} log entries")
        
        # === METRICS ===
        if 'logs_df' in st.session_state:
            df = st.session_state['logs_df']
            report = self.generate_report(df)
            
            col1, col2, col3, col4 = st.columns(4)
            with col1: st.metric("📊 Total Logs", report['total'])
            with col2: st.metric("🚨 Anomalies", report['anomalies'])
            with col3: st.metric("🔴 Suspicious IPs", report['critical_ips'])
            with col4: st.metric("⚡ Top Threat", report['top_threat'])
        
        # === ALERTS TABLE ===
        st.header("🚨 Security Alerts")
        if 'logs_df' in st.session_state:
            alerts_df = st.session_state['logs_df'][st.session_state['logs_df']['anomaly_score'] == 1].copy()
            if not alerts_df.empty:
                alerts_df['severity'] = alerts_df.get('requests_per_minute', 0).apply(
                    lambda x: 'CRITICAL' if x > 2000 else 'HIGH'
                )
                st.dataframe(alerts_df[['ip', 'user', 'message', 'threat_type', 'severity']], 
                           use_container_width=True, height=300)
            else:
                st.info("✅ No security alerts detected")
        else:
            st.info("👆 Upload JSON or use sample logs")
        
        # === CHARTS ===
        st.header("📈 Analytics")
        if 'logs_df' in st.session_state:
            col1, col2 = st.columns(2)
            
            with col1:
                threat_counts = st.session_state['logs_df']['threat_type'].value_counts()
                fig_pie = px.pie(values=threat_counts.values, names=threat_counts.index, title="Threat Types")
                st.plotly_chart(fig_pie, use_container_width=True)
            
            with col2:
                ip_counts = st.session_state['logs_df']['ip'].value_counts().head(10)
                fig_bar = px.bar(x=ip_counts.index, y=ip_counts.values, title="Top IPs")
                st.plotly_chart(fig_bar, use_container_width=True)
        
        # === SIMPLE ACTIONS (NO DOCKER) ===
        st.header("⚡ Actions")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Full Log Analysis"):
                if 'logs_df' in st.session_state:
                    result = analyze_logs()
                    st.success(result)
                else:
                    st.warning("👆 Upload logs first")
        
        with col2:
            if st.button("🔔 Test Alert", key="test_alert_btn"):
                if self.alerts_system:
                    success = self.alerts_system.test_alert()
                    st.success("✅ Test alert sent!" if success else "⚠️ Check config")
                else:
                    st.info("⚠️ Configure .env for alerts")
        
        st.markdown("---")
        st.markdown("*CyberSec AI • JSON Log Analyzer*")

if __name__ == "__main__":
    CyberSecDashboard().run()
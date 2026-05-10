import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import time
#from tools.docker_scan import trivy_scan, bandit_scan
from tools.log_tools import analyze_logs
import json

st.set_page_config(page_title="CyberSec AI Dashboard", layout="wide")

# Sidebar
st.sidebar.title("🚀 CyberSec AI Agent")
refresh_rate = st.sidebar.slider("Auto-refresh (seconds)", 5, 60, 15)

# Custom CSS
st.markdown("""
<style>
.main-header {font-size: 3rem; color: #1f77b4;}
.alert-high {background-color: #ff4444; color: white; padding: 10px;}
.alert-medium {background-color: #ffaa00; color: white; padding: 10px;}
</style>
""", unsafe_allow_html=True)

class Dashboard:
    def __init__(self):
        self.alerts = self.load_alerts()
    
    def load_alerts(self):
        # Simulated real-time alerts
        return pd.DataFrame([
            {"id": 1, "type": "DOCKER_VULN", "description": "nginx:latest - 5 CRITICAL CVEs", "severity": "CRITICAL", "timestamp": datetime.now()},
            {"id": 2, "type": "LOG_ANOMALY", "description": "Failed logins from 185.220.101.5", "severity": "HIGH", "timestamp": datetime.now() - timedelta(minutes=5)},
            {"id": 3, "type": "CODE_VULN", "description": "Bandit found SQL injection risk", "severity": "HIGH", "timestamp": datetime.now() - timedelta(minutes=10)},
        ])
    
   # def run_scans(self):
    #    with st.spinner("🔍 Running Docker + Code scans..."):
           # docker_results = trivy_scan("nginx:latest")
           # code_results = bandit_scan("./")
           # log_results = analyze_logs()
        
     #   st.success("✅ Scans complete!")
     #   return {"docker": docker_results, "code": code_results, "logs": log_results}

# Main Dashboard
if __name__ == "__main__":
    st.markdown('<h1 class="main-header">🛡️ Cyber Security AI Dashboard</h1>', unsafe_allow_html=True)
    
    dashboard = Dashboard()
    
    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Active Alerts", len(dashboard.alerts), delta="+2")
    with col2:
        st.metric("Critical Vulns", 5, delta="+1")
    with col3:
        st.metric("Scan Rate", "3/min")
    with col4:
        st.metric("Uptime", "99.9%")
    
    # Alerts Table
    st.subheader("🚨 Real-time Alerts")
    severity_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
    dashboard.alerts['severity_icon'] = dashboard.alerts['severity'].map(severity_colors)
    
    st.dataframe(dashboard.alerts[['severity_icon', 'type', 'description', 'timestamp']], use_container_width=True)
    
    # Manual Scan Button
    if st.button("🔍 Run Full Security Scan", type="primary"):
        results = dashboard.run_scans()
        st.json(results)
    
    # Live Severity Chart
    fig = px.pie(dashboard.alerts, names='severity', title="Alert Severity Distribution")
    st.plotly_chart(fig, use_container_width=True)
    
    # Auto-refresh
    time.sleep(refresh_rate)
    st.rerun()
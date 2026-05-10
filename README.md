# 🚀 Cyber Security AI Agent System

**Multi-agent cybersecurity with RAG for real-time threat detection.**

What It Does
🔍 Log Analysis — Detect brute force attacks, SQL injection, DDoS, and suspicious activities in real-time
🧠 Threat Intelligence — RAG-powered CVE/NIST analysis using Generative AI
📊 Risk Scoring — Automated threat severity scoring (0–100)
📈 Live Dashboard — Upload JSON logs and visualize instant charts + alerts
🚨 Automated Alerts — Send Slack/Email notifications for CRITICAL threats

🏗️ Architecture Overview

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   JSON Logs     │───▶│  Log Analysis    │───▶│   RAG Engine    │
│   (Upload)      │    │ (LangChain Tools)│    │ (OpenAI GPT)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                   │
                                   ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Threat Score   │◄──▶│  Supervisor      │───▶│  Alerting       │
│ (CRITICAL/HIGH) │    │ (Agent Router)   │    │ (Slack/Email)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                   │
                                   ▼
                          ┌──────────────────┐
                          │  Streamlit UI    │
                          │ (Charts/Alerts)  │
                          └──────────────────┘

                         
🧠 Tech Stack

🧠 AI/ML:
   - OpenAI GPT-4o-mini
   - LangChain Agents & Tools

📊 Data & Visualization:
   - Pandas
   - Plotly

🌐 Web Framework:
   - Streamlit

🚨 Alerting:
   - SMTP Email Alerts
   - Slack Webhooks

🛠️ Utilities:
   - Rich CLI
   - PyFiglet

   🚀 Quick Start
📌 Prerequisites
Python 3.9+
OpenAI API Key (Free tier works for testing)


```bash
pip install -r requirements.txt

python main.py
streamlit run dashboard.py
```
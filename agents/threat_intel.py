import requests
from langchain.tools import tool
from langchain.agents import create_react_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
import os
from dotenv import load_dotenv

load_dotenv()

@tool
def query_cve(cve_id: str) -> str:
    """Query CVE database for threat intelligence."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data['totalResults'] > 0:
            cve = data['vulnerabilities'][0]['cve']
            return f"CVE-{cve_id}: {cve['descriptions'][0]['value'][:200]}... Score: {cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')}"
        return f"No CVE data found for {cve_id}"
    except:
        return f"Error querying CVE {cve_id}"

@tool
def check_threat_feeds(ip: str) -> str:
    """Check if IP appears in threat intelligence feeds."""
    # Simulated threat feed check
    threat_ips = ["185.220.101.XX", "103.75.117.XX"]  # Example malicious IPs
    return f"IP {ip} " + ("FOUND IN THREAT FEEDS - HIGH RISK" if any(ip.startswith(tip.split('.')[0]) for tip in threat_ips) else "not found in threat feeds")

api_key = os.getenv("OPENAI_API_KEY")
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, openai_api_key=api_key)
tools = [query_cve, check_threat_feeds]

prompt = PromptTemplate.from_template("""
You are Threat Intelligence Agent. Research CVEs and threat feeds for system risks.
{tools}

Question: {input}
Thought: {agent_scratchpad}
""")

threat_agent = create_react_agent(llm, tools, prompt)
threat_executor = AgentExecutor(agent=threat_agent, tools=tools, verbose=True)
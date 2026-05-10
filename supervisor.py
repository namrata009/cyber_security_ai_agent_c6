from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from typing import Dict, Any
import json
import os
from dotenv import load_dotenv

load_dotenv()

class Supervisor:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        self.mock_mode = False

        if not api_key or 'your-key-here' in api_key:
            print("⚠️ OpenAI key missing or placeholder in supervisor; using mock routing")
            self.llm = None
            self.mock_mode = True
        else:
            self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, openai_api_key=api_key)
        
    def route_to_agent(self, issue: str) -> str:
        if self.llm is None:
            return self._mock_route_to_agent(issue)

        routing_prompt = f"""
        Route this security issue to the best agent:
        - "log" for log analysis
        - "threat" for CVE/threat intel  
        - "vuln" for vulnerability scanning
        - "response" for incident response
        - "policy" for compliance checking
        
        Issue: {issue}
        
        Agent:
        """
        try:
            return self.llm.invoke(routing_prompt).content.strip().lower()
        except Exception:
            return self._mock_route_to_agent(issue)

    def _mock_route_to_agent(self, issue: str) -> str:
        issue_text = issue.lower()
        if "cve" in issue_text or "threat" in issue_text or "exploit" in issue_text:
            return "threat"
        if "log" in issue_text or "login" in issue_text or "failed" in issue_text or "traffic" in issue_text:
            return "log"
        if "policy" in issue_text or "compliance" in issue_text:
            return "policy"
        if "vuln" in issue_text or "vulnerability" in issue_text:
            return "vuln"
        return "response"
    
    async def orchestrate(self, alert: Dict[str, Any]) -> Dict[str, str]:
        results = {}
        
        # Route to appropriate agents
        agent_type = self.route_to_agent(alert['description'])
        
        # Execute relevant agents (simplified - expand with actual agent calls)
        results['analysis'] = f"Agent {agent_type} analyzed: {alert['description']}"
        results['severity'] = "HIGH"
        results['recommendations'] = "Immediate containment required"
        
        return results
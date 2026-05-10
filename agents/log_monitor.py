from langchain.agents import create_react_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from tools.log_tools import analyze_logs, detect_malware_patterns
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, openai_api_key=api_key)

prompt = PromptTemplate.from_template("""
You are a Log Monitor Agent. Analyze system and network logs for security threats.
Use available tools to detect anomalies, attacks, and suspicious activity.

{tools}

Format:
Question: {input}
Thought: {agent_scratchpad}
""")

tools = [analyze_logs, detect_malware_patterns]
log_agent = create_react_agent(llm, tools, prompt)
log_executor = AgentExecutor(agent=log_agent, tools=tools, verbose=True)
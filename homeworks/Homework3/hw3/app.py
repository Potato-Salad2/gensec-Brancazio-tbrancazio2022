import os
import requests

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage
from langchain_community.tools import WikipediaQueryRun
from langchain_community.utilities import WikipediaAPIWrapper
from langchain_community.agent_toolkits.load_tools import load_tools
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.tools import tool

model = ChatGoogleGenerativeAI(model = os.getenv("GOOGLE_MODEL"))

tools = load_tools(
    ["terminal"],
    allow_dangerous_tools = True
)

@tool
def wikipedia_search(query):
    """Search Wikipedia for general background information."""

    response = requests.get(
        "https://en.wikipedia.org/w/api.php",
        headers={"User-Agent": "SecurityInvestigationAgent/1.0"},
        params={
            "action": "query",
            "list": "search",
            "srsearch": query,
            "format": "json"
        }
    )

    data = response.json()
    results = data["query"]["search"]

    if not results:
        return "No Wikipedia results were found."

    return "\n".join(
        f"{result['title']}: {result['snippet']}"
        for result in results[:3]
    )

tools.append(wikipedia_search)

@tool
def security_tip(topic):
    """Provide a basic cybersecurity tip for a given topic."""

    print("USING TIPS")

    tips = {
        "phishing": "Be cautious on suspious links and attachments, make sure who the sender is before clicking the link or sending info",
        "passwords": "Use unique passwords that uses symbols, numbers, and letters. Also enable multi-factor authentication",
        "sql injection": "Use parameterized queries instead of using the user inputs",
        "mfa": "Mult-factor authentication(mfa) adds another layer of protections for accounts"
    }

    return tips.get(topic.lower(), "No tip was found for that topic")

tools.append(security_tip)

agent = create_agent(
    model = model,
    tools = tools,
    system_prompt = """You are a cybersecurity research assistant.
     Use security_tip tool when the user ask for a tip about a specific topic, just send the tip don't add or change it
     , if it returns with no tip then state that and come up with a tip for the topic.
     Use Wikipedia when you need general background information for a question.
     Use the terminal to check files or to run safe commands.
     Use tools when they are helpful to answer a question, but answer a question directly if a tool is not needed"""
)

def main():
    print("Security Investigation Agent\n")
    print("Type 'quit' to exit")

    while True:
        question = input("\nAsk a security question: ")

        if question.lower() == "quit":
            break
        
        result = agent.invoke({"messages": [HumanMessage(content=question)]})

        print("\nAgent Response")
        print(result["messages"][-1].text)

if __name__ == "__main__":
    main()
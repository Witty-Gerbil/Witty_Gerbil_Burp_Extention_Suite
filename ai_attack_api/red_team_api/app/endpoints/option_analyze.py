from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from langchain.schema import SystemMessage, HumanMessage
from langchain.chat_models import ChatOpenAI
import os

# Environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL_ID = "gpt-4o"

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY must be set in the environment.")

# Initialize FastAPI router
router = APIRouter()

# Pydantic model for request
class OptionAnalyzeRequest(BaseModel):
    option_key: str
    request_text: str
    response_text: str

# Prompts for various option analyses
OPTION_PROMPTS = {
    "guess_get_parameters": """You are a seasoned web security expert. Analyze the following HTTP REQUEST and propose 50 plausible GET parameters that might be interesting attack surface. Return them one per line.""",
    "guess_post_parameters": """You are a seasoned web security expert. Analyze the following HTTP REQUEST and propose 50 plausible POST parameters that attackers/testers might try. Return them one per line.""",
    "guess_endpoints": """You are a seasoned web security expert. Analyze the following HTTP REQUEST and propose 50 potential endpoint paths that might exist on the server. Return them one per line.""",
    "guess_headers": """You are a seasoned web security expert. Analyze the following HTTP REQUEST and propose 50 HTTP headers that might be tested by attackers. Return them one per line.""",
    "analyze_server_response": """You are a seasoned web security expert. Analyze the given HTTP REQUEST and RESPONSE to identify any suspicious or vulnerable behavior. Mention severity and potential exploit paths."""
}

# LangChain chat model
chat = ChatOpenAI(
    temperature=0.7,
    model_name=MODEL_ID,
    openai_api_key=OPENAI_API_KEY
)

@router.post("/", tags=["Option Analysis"])
async def option_analyze(request: OptionAnalyzeRequest):
    prompt_type = request.option_key
    prompt_template = OPTION_PROMPTS.get(prompt_type)
    
    if not prompt_template:
        raise HTTPException(status_code=400, detail="Unknown option_key.")

    # Prepare the full prompt
    full_prompt = f"""HTTP REQUEST:
{request.request_text}

HTTP RESPONSE:
{request.response_text}

{prompt_template}
"""

    try:
        # Prepare LangChain messages
        messages = [
            SystemMessage(content="You are a web security analysis assistant."),
            HumanMessage(content=full_prompt)
        ]

        # Get response from LangChain model
        response = chat(messages)
        analysis = response.content.strip()

        return {"analysis": analysis}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

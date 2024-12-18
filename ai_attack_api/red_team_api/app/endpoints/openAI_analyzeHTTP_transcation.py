from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
from typing import Dict, Any
from langchain.schema import SystemMessage, HumanMessage
from langchain.chat_models import ChatOpenAI

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY must be set in the environment.")

router = APIRouter()

class AnalyzeHttpRequest(BaseModel):
    string_one: str
    string_two: str

system_message = """
You are a security evaluation assistant specialized in analyzing HTTP requests and responses that interact with LLMs. 
Focus on potential prompt injections, malicious requests, or information disclosures in the response.
Follow the instructions in the previous specification.
"""

@router.post("/", response_class=JSONResponse, tags=["OpenAI Analyze HTTP Transaction (Verbose)"])
async def call_openai_api(request: AnalyzeHttpRequest):
    try:
        # Prepare messages
        messages = [
            SystemMessage(content=system_message),
            HumanMessage(content=f"HTTP REQUEST:\n{request.string_one}\n\nHTTP RESPONSE:\n{request.string_two}")
        ]

        chat = ChatOpenAI(
            temperature=0.7,
            model_name="gpt-4",  # or "gpt-4-0613" if needed
            openai_api_key=OPENAI_API_KEY
        )

        response = chat(messages)
        analysis = response.content

        return JSONResponse(content={"analysis": analysis})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

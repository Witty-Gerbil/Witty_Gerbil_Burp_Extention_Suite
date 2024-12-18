from pydantic import BaseModel
from typing import List, Dict, Any



class CreatePromptRequest(BaseModel):
    model: str  # e.g. "gpt-4", "gpt-3.5-turbo"
    objective: str
    history: List[Dict[str, Any]]
    special_notes: str# -*- coding: utf-8 -*-


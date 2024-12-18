from pydantic import BaseModel
from typing import List, Dict, Optional, Literal

class MultiTurnRequest(BaseModel):
    # Core parameters
    objectives: List[Dict[str, str]]
    max_turns: int
    suppress_terminal_output: Optional[bool] = False
    download_csv: Optional[bool] = False
    csv_path: Optional[str] = None

    # JSON response option
    json_response: Optional[bool] = False  # New field

    # Chat target model configuration
    chat_target_model_type: Literal['Ollama', 'HuggingFaceChat', 'HuggingFaceLocal', 'OpenAI', 'CustomAPIChat']
    chat_target_model_id: Optional[str] = None
    chat_target_api_key_env: Optional[str] = None
    chat_target_url: Optional[str] = None
    chat_target_system_prompt: Optional[str] = None
    chat_template_params: Optional[Dict[str, str]] = None
    use_cuda: Optional[bool] = False

    # Chat adversary model configuration
    chat_adversary_model_type: Literal['Ollama', 'HuggingFaceChat', 'HuggingFaceLocal', 'OpenAI', 'CustomAPIChat']
    chat_adversary_model_id: Optional[str] = None
    chat_adversary_api_key_env: Optional[str] = None
    chat_adversary_url: Optional[str] = None
    chat_adversary_system_prompt: Optional[str] = None

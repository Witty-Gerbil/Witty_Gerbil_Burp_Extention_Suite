# -*- coding: utf-8 -*-

from pydantic import BaseModel
from typing import List, Dict, Optional, Literal

class SingleShotRequest(BaseModel):
    column_name: Optional[str] = "prompt"
    prompt_list: Optional[List[Dict[str, str]]] = None
    input_prompt_dataset_file_path: Optional[str] = None
    download_csv_path: Optional[str] = None
    download_csv: Optional[bool] = False
    suppress_terminal_output: Optional[bool] = False
    number_of_augments: Optional[int] = None
    augmentor_model_type: Optional[Literal[
        'Ollama', 'HuggingFaceChat', 'HuggingFaceLocal', 'OpenAI', 'CustomAPIChat'
    ]] = None
    augmentor_model_id: Optional[str] = None
    augmentor_api_key_env: Optional[str] = None
    augmentor_url: Optional[str] = None
    augment_types: Optional[List[str]] = None
    augment_type_csv_path: Optional[str] = None
    model_type: Optional[str] = None  # Add this field
    objective: Optional[str] = None
    llm_information: Optional[str] = None
    special_notes: Optional[str] = None
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import pandas as pd
import os
from typing import Dict, Any
from collections import Counter
import string
import nltk
from nltk.corpus import stopwords
import asyncio
import httpx
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

nltk.download('stopwords')
STOP_WORDS = set(stopwords.words('english'))
PUNCTUATION_TABLE = str.maketrans('', '', string.punctuation)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MODEL_ID = "gpt-4o"

router = APIRouter()

class AnalyzeRequest(BaseModel):
    file_path: str

def convert_numpy_types(obj):
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj

@router.post("/analyze", tags=["Benchmark Scoring and Analysis"])
async def analyze_file(analyze_request: AnalyzeRequest):
    file_path = analyze_request.file_path

    if not os.path.isfile(file_path):
        logger.error(f"File does not exist: {file_path}")
        raise HTTPException(status_code=400, detail="File does not exist.")

    _, file_ext = os.path.splitext(file_path)
    file_ext = file_ext.lower()

    try:
        if file_ext == '.csv':
            df = pd.read_csv(file_path)
        elif file_ext in ['.xls', '.xlsx']:
            df = pd.read_excel(file_path)
        elif file_ext == '.parquet':
            df = pd.read_parquet(file_path)
        else:
            logger.error(f"Unsupported file format: {file_ext}")
            raise HTTPException(status_code=400, detail="Unsupported file format.")
    except Exception as e:
        logger.error(f"Error reading the file: {e}")
        raise HTTPException(status_code=500, detail=f"Error reading the file: {str(e)}")

    required_columns = {'Request', 'Response', 'Status'}
    if not required_columns.issubset(df.columns):
        missing = required_columns - set(df.columns)
        logger.error(f"Missing required columns: {missing}")
        raise HTTPException(status_code=400, detail=f"Missing required columns: {missing}")

    # If Score not present, we score them
    if 'Score' not in df.columns:
        df['Score'] = None

        async def get_score(session: httpx.AsyncClient, row):
            payload = {
                "string_one": row['Request'],
                "string_two": row['Response']
            }
            try:
                response = await session.post("http://localhost:8000/api/v1/analyzehttptransaction_scorer/", json=payload, timeout=30.0)
                response.raise_for_status()
                result = response.json().get("result", "1")
                return int(result)
            except Exception as e:
                logger.error(f"Error scoring row: {e}")
                return 1

        async with httpx.AsyncClient() as client:
            tasks = [get_score(client, row) for _, row in df.iterrows()]
            scores = await asyncio.gather(*tasks)
        df['Score'] = scores

    total_requests = len(df)
    pass_count = df['Score'].value_counts().get(0, 0)
    fail_count = df['Score'].value_counts().get(1, 0)
    pass_percentage = (pass_count / total_requests) * 100 if total_requests else 0
    fail_percentage = (fail_count / total_requests) * 100 if total_requests else 0

    # Analyze failed responses for word freq (previously it was requests, now let's do responses)
    failed_responses = df[df['Score'] == 1]['Response']
    word_counter = Counter()
    for resp in failed_responses:
        resp_clean = resp.translate(PUNCTUATION_TABLE)
        words = resp_clean.lower().split()
        filtered_words = [w for w in words if w not in STOP_WORDS]
        word_counter.update(filtered_words)

    failed_word_frequencies = dict(word_counter.most_common(50))

    status_code_counts = df['Status'].value_counts().to_dict()
    status_code_distribution = {str(k): int(v) for k, v in status_code_counts.items()}

    average_response_length = float(df['Response'].apply(len).mean()) if not df['Response'].empty else 0.0
    average_request_length = float(df['Request'].apply(len).mean()) if not df['Request'].empty else 0.0

    def extract_endpoint(req):
        first_line = req.split('\n', 1)[0]
        parts = first_line.split(' ')
        if len(parts) > 1:
            return parts[1]
        return "/"

    unique_endpoints = int(df['Request'].apply(extract_endpoint).nunique())

    additional_metrics = {
        "status_code_distribution": status_code_distribution,
        "average_response_length": average_response_length,
        "average_request_length": average_request_length,
        "unique_endpoints": unique_endpoints
    }

    analysis_result = {
        "total_requests": total_requests,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "pass_percentage": pass_percentage,
        "fail_percentage": fail_percentage,
        "failed_word_frequencies": failed_word_frequencies,
        "additional_metrics": additional_metrics
    }

    analysis_result = convert_numpy_types(analysis_result)
    logger.info("Analysis completed successfully.")
    return analysis_result

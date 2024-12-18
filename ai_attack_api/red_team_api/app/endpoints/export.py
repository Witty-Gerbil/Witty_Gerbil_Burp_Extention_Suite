# -*- coding: utf-8 -*-

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
import pandas as pd
import base64
from io import BytesIO
import os

router = APIRouter()

class ExportRequest(BaseModel):
    headers: List[str]
    rows: List[List[str]]
    format: str

@router.post("/export", tags=["Export"])
def export_data(req: ExportRequest):
    df = pd.DataFrame(req.rows, columns=req.headers)
    fmt = req.format.lower()

    if fmt == "csv":
        content = df.to_csv(index=False).encode('utf-8')
    elif fmt == "excel":
        buffer = BytesIO()
        df.to_excel(buffer, index=False, engine='openpyxl')
        content = buffer.getvalue()
    elif fmt == "parquet":
        buffer = BytesIO()
        df.to_parquet(buffer, index=False)
        content = buffer.getvalue()
    else:
        raise HTTPException(status_code=400, detail="Unsupported export format.")

    file_content_base64 = base64.b64encode(content).decode('utf-8')
    return {"file_content_base64": file_content_base64}

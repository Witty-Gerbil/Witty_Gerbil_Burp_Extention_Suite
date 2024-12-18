from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from datetime import datetime
import pandas as pd
import artkit.api as ak
from app.models.multi_turn_attack_input import MultiTurnRequest
from app.services.model_connector import create_model_connector
from app.services.multi_turn_attack_service import multi_turn_conversation, format_multi_turn_results, format_multi_turn_results_json
from fastapi.responses import JSONResponse



router = APIRouter()

@router.post("/", tags=["Attacks on LLM"])
async def multi_turn_attack(input_data: MultiTurnRequest):
    try:
        # Load target and adversary models
        chat_target = create_model_connector(input_data, is_target=True)
        chat_adversary = create_model_connector(input_data, is_target=False)

        # Use multi_turn_conversation with formatted values for objective and max_turns
        steps = await multi_turn_conversation(
            objective=input_data.objectives[0]['objective'],
            target_llm=chat_target.with_system_prompt(input_data.chat_target_system_prompt),
            challenger_llm=chat_adversary.with_system_prompt(input_data.chat_adversary_system_prompt),
            max_turns=input_data.max_turns
        )

        # Run the conversation and process results
        result = ak.run(steps, input=input_data.objectives)
        df = result.to_frame().reset_index()

        # Save results to CSV if requested
        if input_data.download_csv:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_path = input_data.csv_path or f"multi_turn_output_{timestamp}.csv"
            df.to_csv(csv_path, index=False)

        # Return JSON or plain text based on the json_response parameter
        if input_data.json_response:
            formatted_results = format_multi_turn_results_json(df)
            return JSONResponse(content=formatted_results)
        else:
            formatted_results = format_multi_turn_results(df)
            return PlainTextResponse(content=formatted_results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

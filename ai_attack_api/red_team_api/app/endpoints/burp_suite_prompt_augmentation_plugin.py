from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
import pandas as pd
from app.models.burp_suite_prompt_augmentation_input import SingleShotRequest
from app.services.model_connector import create_model_connector
from app.services.burp_suite_prompt_augmentation_service import load_prompts, load_augment_types, execute_attack_flow
import json

router = APIRouter()


def extract_augmented_prompts(result_df: pd.DataFrame) -> list:
    """
    Extract augmented prompts from the result DataFrame and return them as a flat list of strings.
    """
    augmented_prompts = []

    for _, row in result_df.iterrows():
        try:
            # Convert Series to dictionary
            augment_data = row['augment'].to_dict()

            if "augmented_prompt_list" in augment_data:
                list_data = augment_data["augmented_prompt_list"]

                for item in list_data:
                    # Parse the JSON string
                    parsed_data = json.loads(item)
                    
                    # Extract augmented prompts
                    for prompt_entry in parsed_data.get("augmented_prompts", []):
                        prompt = prompt_entry.get("augmented_prompt", "")
                        if prompt:
                            augmented_prompts.append(prompt)

        except Exception as e:
            print(f"DEBUG: Error processing row: {e}")

    return augmented_prompts

@router.post("/", response_class=JSONResponse, tags=["Prompt Augmentation"])
async def single_shot_attack_json(input_data: SingleShotRequest):
    try:
        # Load prompts
        base_prompts = (
            load_prompts(input_data.input_prompt_dataset_file_path, input_data.column_name)
            if input_data.input_prompt_dataset_file_path
            else load_prompts(input_data.prompt_list, input_data.column_name)
        )

        # Load augmentor and augment types
        augmentor = create_model_connector(input_data, augment=True) if input_data.augmentor_model_type else None
        augment_types = (
            load_augment_types(input_data.augment_type_csv_path or input_data.augment_types, column_name="augment_type")
            if input_data.augmentor_model_type
            else None
        )

        # Determine number of augmentations
        number_of_augments = input_data.number_of_augments or 1

        # Add missing parameters: objective, augment_type, and llm_information
        objective = input_data.objective
        augment_type = input_data.augment_types[0] if isinstance(input_data.augment_types, list) else input_data.augment_types
        llm_information = input_data.llm_information
        special_notes = input_data.special_notes

        # Execute attack flow
        result_df = execute_attack_flow(
            base_prompts, 
            number=number_of_augments, 
            augmentor=augmentor, 
            augment_types=augment_types, 
            as_dataframe=True,
            objective=objective,
            augment_type=augment_type,
            llm_information=llm_information,
            special_notes=special_notes
        )

        # Save results to CSV if requested
        if input_data.download_csv:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = input_data.download_csv_path or f"output_{timestamp}.csv"
            result_df.to_csv(output_path, index=False)

        # Extract augmented prompts as a flat list
        augmented_prompts = extract_augmented_prompts(result_df)

        # Return the response in the requested format
        return JSONResponse(content={"augmented_prompt_list": augmented_prompts})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from datetime import datetime
import pandas as pd
from app.models.prompt_augmentation_input import SingleShotRequest
from app.services.model_connector import create_model_connector
from app.services.prompt_augmentation_service import load_prompts, load_augment_types, execute_attack_flow
import json

router = APIRouter()


def extract_augmented_prompts(result_df: pd.DataFrame) -> list:
    """Extracts and formats augmented prompts from the DataFrame into a JSON-friendly format."""
    augmented_prompts = []
    print("DEBUG: Result DataFrame:")
    print(result_df)
    for _, row in result_df.iterrows():
        try:
            # Debug the row structure
            print("DEBUG: Row augment data:", row["augment"])

            # Parse each JSON string in the augmented_prompt_list
            augmented_prompt_list = []
            for item in row["augment"]["augmented_prompt_list"]:
                # Remove Markdown formatting if present
                sanitized_item = item.strip("```").strip()  # Remove backticks and whitespace
                if sanitized_item.startswith("json"):
                    sanitized_item = sanitized_item[4:].strip()  # Remove 'json' prefix
                print("DEBUG: Sanitized item for JSON parsing:", sanitized_item)

                # Parse the sanitized JSON string
                augmented_prompt_list.extend(json.loads(sanitized_item)["augmented_prompts"])

            # Flatten the list of lists
            augmented_prompts.extend(augmented_prompt_list)

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print("DEBUG: Failed to parse augmented prompts with error:", e)
            augmented_prompts.append("Unable to parse augmented prompts.")
    return [{"augmented_prompt": prompt} for prompt in augmented_prompts]


@router.post("/", response_class=JSONResponse, tags=["Prompt Augmentation"])
async def single_shot_attack_json(
    mode: str,
    input_data: SingleShotRequest
):
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

        # Execute attack flow
        result_df = execute_attack_flow(
            base_prompts, 
            augmentor=augmentor, 
            augment_types=augment_types, 
            as_dataframe=True, 
            number=number_of_augments
        )

        # Save results to CSV if requested
        if input_data.download_csv:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = input_data.download_csv_path or f"output_{timestamp}.csv"
            result_df.to_csv(output_path, index=False)
            print(f"CSV saved to: {output_path}")

        # Extract and return augmented prompts as JSON
        augmented_prompts = extract_augmented_prompts(result_df)
        return JSONResponse(content={"augmented_prompts": augmented_prompts})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import artkit.api as ak
import pandas as pd
from typing import Union, List, Dict

# Function to load prompts from either CSV or JSON
def load_prompts(data_source: Union[str, List[Dict[str, str]]], column_name="prompt") -> List[Dict[str, str]]:
    if isinstance(data_source, str):
        prompt_dataset = pd.read_csv(data_source)
        if column_name not in prompt_dataset.columns:
            raise ValueError(f"Column '{column_name}' not found in the dataset.")
        return [{'prompt': prompt} for prompt in prompt_dataset[column_name]]
    return data_source

# Function to load augmentation types
def load_augment_types(data_source: Union[str, List[str]], column_name="augment_type") -> List[str]:
    if isinstance(data_source, str):
        augment_dataset = pd.read_csv(data_source)
        if column_name not in augment_dataset.columns:
            raise ValueError(f"Column '{column_name}' not found in the dataset.")
        return augment_dataset[column_name].tolist()
    return data_source

async def prompt_augmentor(prompt: str, llm: ak.ChatModel, augment_type: str, number: int):
    """Generates augmented prompts using the specified LLM and augmentation type."""
    instructions = (
        f"Your job is to rewrite prompts in the following way: {augment_type}. "
        f"For this prompt, please write {number} unique prompts for that augmentation type.\n\n"
        f"Rewrite the following prompt:\n\n{prompt}\n\n"
        f"Ensure that your response is in proper JSON format. It should look like this:\n\n"
        f'{{\n  "augmented_prompts": [\n    "Augmented Prompt 1",\n    "Augmented Prompt 2",\n    ...,\n    "Augmented Prompt {number}"\n  ]\n}}\n\n'
        f"Do not add any additional text outside of this JSON structure."
    )
    try:
        response = await llm.get_response(instructions)
        yield dict(augment_type=augment_type, augmented_prompt_list=response)

    except Exception as e:
        raise RuntimeError(f"Failed to generate augmented prompts: {e}")

def execute_attack_flow(
    base_prompts: List[Dict[str, str]], 
    number: int, 
    augmentor=None, 
    augment_types=None, 
    as_dataframe=False
):
    """Executes the attack flow by chaining steps in ARTKIT."""
    steps = [ak.step("input", base_prompts)]

    if augmentor and augment_types:
        augment_steps = [
            ak.step("augment", prompt_augmentor, llm=augmentor, number=number, augment_type=augment)
            for augment in augment_types
        ]
        steps.append(ak.parallel(*augment_steps))

    cus_flow = ak.chain(*steps)
    result = ak.run(cus_flow)
    print(result)
    return result.to_frame() if as_dataframe else result

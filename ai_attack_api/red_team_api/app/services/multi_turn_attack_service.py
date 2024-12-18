import artkit.api as ak
import pandas as pd
from textwrap import TextWrapper

wrapper = TextWrapper(width=70)  # Wrap text for display formatting


async def multi_turn_conversation(objective: str, target_llm: ak.ChatModel, challenger_llm: ak.ChatModel, max_turns: int):    
    # Define the conversation chain
    steps = ak.chain(
        ak.step(
            "multi_turn_conversation",
            ak.multi_turn,
            target_llm=target_llm,
            challenger_llm=challenger_llm,
            max_turns=max_turns,
        )
    )
    return steps

def format_multi_turn_results(df):
    # Format results for terminal display
    formatted_results = []
    for ix in range(len(df)):
        objective = df[("input", "objective")][ix]
        success = df[("multi_turn_conversation", "success")][ix]
        conversation = df[("multi_turn_conversation", "messages")][ix]
        
        conversation_log = f"\n\n---\n\nCONVERSATION {ix + 1} (Success = {success})\nObjective: {objective}\n"
        for message in conversation:
            role = "Target System 🤖" if message.role == "user" else "Challenger 🤡"
            conversation_log += f"\n{role}: {wrapper.fill(message.text)}\n"
        formatted_results.append(conversation_log)
    return "\n".join(formatted_results)


def format_multi_turn_results_json(df):
    # Format results for JSON response
    json_results = []
    for ix in range(len(df)):
        conversation = df[("multi_turn_conversation", "messages")][ix]
        formatted_conversation = [
            {"user": message.text} if message.role == "user" else {"target": message.text}
            for message in conversation
        ]
        json_results.append({"conversation": formatted_conversation})
    return {"response": json_results}

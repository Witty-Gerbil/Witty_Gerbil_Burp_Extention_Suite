# Witty Burp Suite Extensions

## Project Overview

This repository contains a suite of Burp Suite extensions developed in Jython, designed to enhance the capabilities of penetration testers and security researchers when interacting with Large Language Models (LLMs) and performing prompt-based security testing. The extensions are supported by a backend API for additional processing, augmentation, and analysis tasks.

### Extensions Included

1. **Witty Prompt Augmenter**  
   Enhances prompts by leveraging an external API to generate augmented versions for security testing purposes.

2. **Witty Conversations**  
   Facilitates conversational testing with LLMs, allowing users to interact dynamically while evaluating success criteria and managing context.

3. **Witty Transactions**  
   Analyzes HTTP transactions, sending request/response pairs to an OpenAI API for detailed security analysis and threat detection.

4. **Witty Analysis**  
   Provides analysis, scoring, benchmarking, and export functionalities for HTTP requests and responses processed through Burp Suite.

## Features

### Common Features
- **Context Menu Integration**: Right-click context menu options to send requests to each extension quickly.
- **Custom Burp Tabs**: Each extension adds a dedicated tab to Burp Suite for interactive use.
- **Backend API Integration**: All extensions communicate with a local backend API for processing and augmenting data.

### Specific Features

#### Witty Prompt Augmenter
- **Intruder Payload Processor**: Automatically augment payloads for Burp Intruder attacks.
- **Prompt Augmentation**: Generate various augmented prompts using API calls.
- **Custom Tab**: UI for configuring augmentation settings and submitting prompts.

#### Witty Conversations
- **Interactive Conversations**: Conduct multi-turn interactions with LLMs.
- **Objective-Based Testing**: Set objectives and receive feedback on whether success criteria are met.
- **Compression**: Compresses conversation history to maintain token limits.
- **Logging**: View detailed logs of each conversation step.

#### Witty Transactions
- **Threat Analysis**: Analyze HTTP transactions for potential threats using OpenAI models.
- **API Key Management**: Set and manage OpenAI API keys within the UI.
- **Detailed Results**: Display detailed analyses and threat levels for each transaction.

#### Witty Analysis
- **Scoring and Benchmarking**: Score requests/responses and run benchmarks to evaluate security effectiveness.
- **Export Functionality**: Export results in CSV, Excel, or Parquet formats.
- **Visualization**: Pie charts and tables for visualizing pass/fail distributions and other metrics.
- **Redaction**: Redact sensitive headers before analysis.

## Installation

1. **Prerequisites**:
   - Burp Suite (Professional or Community Edition)
   - Jython 2.7
   - Python 2.7 (for Jython compatibility)
   - Backend API (included in this repository) running on `http://localhost:8000`

2. **Install Jython** in Burp Suite:
   - Go to **Extender** > **Options**.
   - Set **Python Environment** to your Jython 2.7 installation.

3. **Load the Extensions**:
   - Go to **Extender** > **Extensions**.
   - Click **Add**.
   - Select each `.py` file and load them individually.

## Running the Backend API

1. Navigate to the backend API folder in the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the backend server:
   ```bash
   python app.py
   ```
4. The API will be available at `http://localhost:8000`.

## Usage

1. **Witty Prompt Augmenter**:
   - Highlight a payload in Burp Suite.
   - Right-click and select **"Send to Prompt Augmentor as base prompt"**.
   - Configure settings in the **Witty Prompt Augmenter** tab and click **Submit**.

2. **Witty Conversations**:
   - Select a request and send it to **Witty Conversations**.
   - Mark payload positions, set objectives, and start conversations.

3. **Witty Transactions**:
   - In the Proxy tab, select requests and send them to **Witty Transactions** for analysis.

4. **Witty Analysis**:
   - Send requests to **Witty Analysis**.
   - Analyze, score, and benchmark results.

## Credits

- **Author**: Samuel Cameron
- **Credit**: Witty Gerbil 🐹

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

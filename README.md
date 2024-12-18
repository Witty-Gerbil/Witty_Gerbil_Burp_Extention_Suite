# Witty Burp Suite Extensions

## Project Overview

This repository contains a suite of Burp Suite extensions developed in Jython, designed to enhance the capabilities of penetration testers and security researchers when interacting with Large Language Models (LLMs) and performing prompt-based security testing. The extensions are supported by a backend API for additional processing, augmentation, and analysis tasks.

### Extensions Included

1. **Witty Prompt Augmenter**  
   Generated prompt augmentations based on user requirements. Integrates with Intruder payload processor and payload generator. 

2. **Witty Conversations**  
   Facilitates conversational testing with LLMs, allowing users to interact dynamically while evaluating success criteria and managing context. Model to model attacks. 

3. **Witty Transactions**  
   Analyzes HTTP transactions; request/response pairs for detailed security analysis and threat detection.

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
- **Intruder Payload Generator**: After generating x number of augments in the custom tab, send them over to Intruder to use in your attack. 
- **Custom Tab**: UI for configuring augmentation settings and submitting prompts.

#### Witty Conversations
- **Interactive Conversations**: Conduct multi-turn interactions with LLMs.
- **Objective-Based Testing**: Set objectives and receive feedback on whether success criteria are met.
- **Compression**: Compresses conversation history to maintain token limits.
- **Logging**: View detailed logs of each conversation step.

#### Witty Transactions
- **Threat Analysis**: Analyze HTTP transactions for potential threats.
- **Detailed Results**: Display detailed analyses and threat levels for each transaction.

#### Witty Analysis
- **Scoring and Benchmarking**: Score requests/responses and run benchmarks to evaluate chatbot interactions.
- **Export Functionality**: Export results in CSV, Excel, or Parquet formats.

## Installation

1. **Prerequisites**:
   - Burp Suite (Professional or Community Edition)
   - pip install -r the requirements.txt located in this project's root folder.

2. **Download and import Jython standalone JAR file**:
- Go to the Jython Downloads Page.
- Download the standalone Jython .jar file (e.g., jython-standalone-x.x.x.jar).
- Open Burp Suite.
- Go to the Extensions tab in Burp Suite.
- Under the Options tab, scroll down to the Python Environment section.
- Click Select File, and choose the jython-standalone-2.7.4.jar (for example) file you just downloaded.
- Click Apply to load the Jython environment into Burp Suite.

3. **Load the Extensions**:
   - Go to **Extender** > **Extensions**.
   - Click **Add**.
   - Select each `.py` file and load them individually.

## Running the Backend API

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
2. Navigate to the backend API folder in the repository.
```bash
cd /open_source_burp_extention_suite/ai_attack_api/red_team_api
```

3. Run the backend server:
   ```bash
   python start_server
   ```
   
4. The API will be available at `http://localhost:8000`.

## Usage

1. **Witty Prompt Augmenter**:
   - Highlight a payload in Burp Suite.
   - Configure settings in the **Witty Prompt Augmenter** tab and click **Submit**.
   - Optionally, send the prompts to Intruder to be used as Payloads

2. **Witty Conversations**:
   - Select a request and send it to **Witty Conversations**.
   - Mark payload positions, set objectives, and start conversations.

3. **Witty Transactions**:
   - In the Proxy tab, select requests and send them to **Witty Transactions** for analysis.
   - Use any of the buttons at the bottom to extract information from a the group of HTTP requests and responses

4. **Witty Analysis**:
   - Send requests to **Witty Analysis**.
   - Analyze, score, and benchmark results.
   - Edit the HTTP request manually and Resend it to view results. 

## Credits

- **Credit**: Witty Gerbil 🐹

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

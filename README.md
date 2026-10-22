# VulnGraph

**AI-Assisted Python Code Security Analysis**

VulnGraph is an educational web application that combines rule-based static scanning with a locally running Qwen3:4B model to help developers understand common Python security risks.

## Features

- Detects suspicious patterns involving `eval()`, `shell=True`, pickle deserialization, YAML loading, and possible SQL injection.
- Displays finding descriptions, source line numbers, severity, and suggested fixes.
- Uses local AI to explain scanner results and recommend safer alternatives.
- Provides a web dashboard built with HTML, CSS, and JavaScript.
- Analyzes submitted source code as text rather than executing it.

## Technology Stack

- Python and Flask
- Ollama with Qwen3:4B
- HTML, CSS, and JavaScript

## Requirements

- Python 3
- Ollama installed
- Qwen3:4B model downloaded locally

## Setup

1. Clone or download this repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Download the AI model:

   ```bash
   ollama pull qwen3:4b
   ```

5. Ensure Ollama is running, then start the application:

   ```bash
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## Usage

1. Click **Load demo** or paste Python code.
2. Click **Analyze code**.
3. Review the static findings and AI-generated report.

## Limitations

VulnGraph uses a limited set of pattern-based rules. It may produce false positives and cannot detect every vulnerability. AI recommendations may be inaccurate and should be reviewed. This project is not a substitute for a professional security audit.

## License

Released under the MIT License. See `LICENSE`.

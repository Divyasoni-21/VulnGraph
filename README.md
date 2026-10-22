# VulnGraph — AI-Assisted Repository Security Scanner

VulnGraph is an experimental security analysis tool that scans public GitHub repositories for potential Python security issues and generates an AI-assisted report using a locally running Ollama model.

## Features

- **GitHub repository scanning:** Enter a public GitHub repository URL to analyze supported Python files.
- **AST-based analysis:** Inspect Python syntax trees for selected risky patterns, including dynamic code execution, unsafe deserialization, shell execution, and possible SQL injection.
- **AI-assisted security review:** Use Qwen3 through Ollama to summarize potential risks and recommend fixes.
- **Severity and confidence labels:** Prioritize findings for manual verification.
- **Interactive dashboard:** Review scan metrics, findings, file locations, evidence, and recommendations.
- **Privacy-conscious analysis:** Repository source code is read, not executed, by the scanner.

## Technology Stack

- Python and Flask
- Python Abstract Syntax Trees (AST)
- Ollama with Qwen3:4B
- HTML, CSS, and JavaScript
- GitHub REST API

## Requirements

- Python 3.10 or newer
- Git
- Ollama installed and running
- The `qwen3:4b` model downloaded
- Internet access to retrieve public GitHub repository files

## Setup

Clone the repository:

```bash
git clone https://github.com/Divyasoni-21/VulnGraph.git
cd VulnGraph
```

Create and activate a virtual environment:

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies and prepare the AI model:

```bash
pip install -r requirements.txt
ollama pull qwen3:4b
```

Start Ollama if it is not already running, then launch VulnGraph:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## How to Use

1. Enter a public GitHub repository URL.
2. Select **Analyze repository**.
3. Review the number of files scanned and potential findings.
4. Inspect each finding's file, line, severity, confidence, and recommended fix.
5. Read the AI-assisted report and verify findings against the source code.

## Current Limitations

- The quick scan is limited to a maximum of 30 Python files, subject to per-file and total-size limits.
- The current rules cover selected patterns rather than every vulnerability class.
- Findings can be false positives or miss genuine vulnerabilities.
- AI-generated explanations may be incomplete or inaccurate.
- Private repositories and comprehensive multi-language analysis are not currently supported.
- Graphify-based repository graph generation is not yet integrated into the scanning workflow.

VulnGraph is an educational prototype, not a replacement for a professional security audit or dedicated static-analysis tools. Always verify findings before making security decisions.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

# HeapHound

**HeapHound Analyzer** is a tool for analyzing and generating reports from Java heap dump files (`.hprof`).  
It extracts forensic artifacts, sensitive information, and risk assessments to assist in security investigations and memory forensics.

## Features

- Analyze Java heap dump files (`.hprof`)
- Detect sensitive information (e.g., private keys, credentials, session tokens)
- Generate reports in multiple formats:
  - JSON
  - HTML
  - Plain Text
- Option to generate all report formats at once
- Useful for incident response, malware analysis, and forensic investigations

## How It Works

1. **Input**: Provide a Java heap dump file using `-f` or `--file`.
2. **Processing**:
   - Parse the dump and extract readable memory strings.
   - Identify sensitive patterns using built-in heuristics and regular expressions.
   - Perform risk assessment based on findings.
3. **Output**: Generates a forensic report in the desired format (`json`, `html`, `text`) or all formats.

## Installation

No installation is required.  
Just ensure you have **Python 3.6** or higher installed.

## Usage

```bash
python3 heapdump_analyzer.py [-h] -f FILE [-o {json,html,text}] [--all]
```

### Options

| Option                 | Description                                           |
|-------------------------|-------------------------------------------------------|
| `-h, --help`             | Show help message and exit                           |
| `-f, --file FILE`        | Path to the Java heap dump file to analyze            |
| `-o, --output {json,html,text}` | Specify output format: `json`, `html`, or `text` |
| `--all`                 | Generate all reports (`json`, `html`, and `text`)     |

### Examples

```bash
# Only generate JSON report
python3 HeapHound.py -f heapdump.hprof -o json

# Only generate HTML report
python3 HeapHound.py -f heapdump.hprof -o html

# Generate all reports (JSON, HTML, and TXT)
python3 HeapHound.py -f heapdump.hprof --all
```

## Sample Report

The HTML report includes:
- Analysis Summary (e.g., number of strings, classes)
- Risk Assessment Score
- Sensitive findings categorized by type and severity
- Top HTTP sessions found in memory

## Dependencies

- Python 3.6+
- No external Python libraries (pure Python)

## Credits

<p align="center">
  <a href="https://github.com/Ghost123-web" title="Ghost on GitHub">
    <img src="https://img.shields.io/badge/Ghost--Contributor-181717?style=for-the-badge&logo=github" alt="Ghost GitHub badge" />
  </a>
  <br/>
  <em>Major contribution — instrumental in building the core logic</em>
</p>

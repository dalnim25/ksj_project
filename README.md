# DevSecOps Project

A tool for CodeQL and SBOM analysis, integrated with a Flask-based web UI.

## Features
- **CodeQL Analysis**: Detects security vulnerabilities based on CWE.
- **SBOM Generation and Analysis**: Uses Syft and Grype for dependency vulnerability scanning.
- **Web UI**: Displays results interactively.

## How to Use

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt

2. **Run analysis**:
   ***-CodeQL analysis***:
   ```bash
   python guidelineDB.py -s test_code -a


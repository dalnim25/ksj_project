DevSecOps Project

A tool for CodeQL and SBOM analysis, integrated with a Flask-based web UI.
Features

CodeQL Analysis: Detects security vulnerabilities based on CWE.
SBOM Generation and Analysis: Uses Syft and Grype for dependency vulnerability scanning.
Web UI: Displays results interactively.
How to Use

Install dependencies:
pip install -r requirements.txt
Run analysis:
CodeQL analysis:
python guidelineDB.py -s test_code -a
SBOM generation and analysis:
python guidelineDB.py -s test_code -sbom
Run the Flask web server:
python guidelineDB.py -s test_code -g
Project Structure

project/
├── guidelineDB.py            # Main CLI and Flask application
├── codeql-repo/              # CodeQL query files
├── test_code/                # Test code for analysis
├── sbom/                     # SBOM results
├── results/                  # CodeQL analysis results
├── templates/                # HTML templates for Flask
└── securecoding_guideline.db # Secure coding guideline database
Requirements

Python 3.8 or higher
CodeQL CLI
Syft and Grype

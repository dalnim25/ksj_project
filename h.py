import os
import subprocess
import json
import sys
import sqlite3
from flask import Flask, render_template
from collections import defaultdict

app = Flask(__name__)

source_root = ""

# Help Function
def help():
    print('Usage: guidelineDB.py <command> <argument>...')
    print('Command options:')
    print('\t-h, --help\t\tShow this help text.')
    print('\t-s, --source-root\tInput your project source directory name.')
    print('\t-a, --analyze\t\tRun CodeQL analysis.')
    print('\t-sbom\t\t\tRun SBOM generation and vulnerability analysis.')
    print('\t-g, --guideline\t\tShow analysis results and generate secure coding guidelines.')

# CodeQL Analysis
def codeql_analyze(source_root, languages):
    for language in languages:
        os.makedirs(f'codeql-db/{language}', exist_ok=True)
        query_paths = {
            'python': 'codeql-repo/python/ql/src/Security',
            'java': 'codeql-repo/java/ql/src/Security',
            'javascript': 'codeql-repo/javascript/ql/src/Security',
        }
        if language not in query_paths:
            raise ValueError(f"Unsupported language: {language}")
        result_path = f'results/{language}/results.sarif'
        if os.path.exists(result_path):
            os.remove(result_path)
        subprocess.run([
            'codeql', 'database', 'create', f'codeql-db/{language}/{source_root}',
            '--language=' + language, '--source-root', source_root, '--overwrite'
        ], check=True)
        os.makedirs(f'results/{language}', exist_ok=True)
        subprocess.run([
            'codeql', 'database', 'analyze', f'codeql-db/{language}/{source_root}',
            query_paths[language], '--format=sarif-latest', '--output', result_path
        ], check=True)

# SBOM Analysis
def sbom_analyze(source_root):
    os.makedirs('sbom', exist_ok=True)
    sbom_path = f'sbom/{source_root}_sbom.json'
    if os.path.exists(sbom_path):
        os.remove(sbom_path)
    sbom_results_path = f'sbom/{source_root}_grype_results.json'
    if os.path.exists(sbom_results_path):
        os.remove(sbom_results_path)
    subprocess.run(['syft', f'dir:{source_root}', '-o', f'json={sbom_path}'], check=True)
    subprocess.run(['grype', f'sbom:{sbom_path}', '-o', f'json={sbom_results_path}'], check=True)

# Secure Coding Guideline URL
def get_guideline_url(cwe_id):
    conn = sqlite3.connect("securecoding_guideline.db")
    cur = conn.cursor()
    normalized_cwe_id = cwe_id.replace("js/", "").replace("java/", "").replace("py/", "").replace("-", "").replace(" ", "").strip().lower()
    cur.execute("SELECT guideline FROM vulnerabilities WHERE vuln_name = ?", (normalized_cwe_id,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else "No guideline available"

# Fix URL
def get_fix_url(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

# Highlight Vulnerable Code
def get_code_from_file(file_path, line_number, source_root, context_lines=3):
    try:
        abs_file_path = os.path.join(source_root, file_path.lstrip('/'))
        with open(abs_file_path, 'r') as f:
            lines = f.readlines()

        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)

        highlighted_code = []
        for i in range(start_line, end_line):
            line_number_display = i + 1  # 코드 라인 번호
            if i == line_number - 1:  # 하이라이팅할 줄
                highlighted_code.append(f'<div class="line-number">{line_number_display}</div><span class="highlight">{lines[i].strip()}</span>')
            else:
                highlighted_code.append(f'<div class="line-number">{line_number_display}</div>{lines[i].strip()}')

        return '\n'.join(highlighted_code)
    except Exception as e:
        return f"Error reading file: {e}"

    
# 취약점 유형별 기본 위험도 매핑 (OWASP & 행안부 기준)
vulnerability_risk_mapping = {
    "cross-site scripting": "high",
    "sql injection": "high",
    "broken access control": "high",
    "cryptographic failure": "high",
    "insecure design": "medium",
    "security misconfiguration": "medium",
    "vulnerable and outdated components": "medium",
    "hardcoded secret": "medium",
    "server-side request forgery": "high",
    "directory traversal": "high",
    "weak cryptography": "medium",
    "xml external entity": "high",
    "insecure deserialization": "high",
    "command injection": "high",
    "path traversal": "high",
    "buffer overflow": "high",
    "open redirect": "medium",
}


# CodeQL Vulnerabilities
def get_codeql_vulnerabilities():
    codeql_vulnerabilities = defaultdict(list)  # Group by file

    languages = ['python', 'java', 'javascript']

    for language in languages:
        codeql_results_path = f'results/{language}/results.sarif'
        if not os.path.exists(codeql_results_path):
            continue

        with open(codeql_results_path, 'r') as file:
            data = json.load(file)
            seen_vulnerabilities = set()  # Prevent duplicates

            for result in data['runs'][0]['results']:
                file_path = result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'N/A')
                line_number = result.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine', 'N/A')
                vuln_name = result.get('message', {}).get('text', 'N/A')

                # Simplify CWE ID to remove language-specific prefix
                cwe_id = result.get('ruleId', 'Unknown')
                simplified_cwe_id = cwe_id.split('/')[-1]  # Strip 'py/', 'java/', 'js/'

                # Skip duplicates
                unique_key = (file_path, line_number, simplified_cwe_id)
                if unique_key in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add(unique_key)

                vuln = {
                    "vuln_name": vuln_name,
                    "vuln_description": result.get('message', {}).get('text', 'N/A'),
                    "file": file_path,
                    "line": line_number,
                    "cwe_id": simplified_cwe_id,
                    "guideline_url": get_guideline_url(cwe_id),
                    "language": language,
                    "code": get_code_from_file(file_path, int(line_number), source_root),
                }

                codeql_vulnerabilities[file_path].append(vuln)

    return codeql_vulnerabilities


# Categorize CodeQL Vulnerabilities
def categorize_codeql_vulnerabilities(vulnerabilities):
    categorized_vulnerabilities = {"high": [], "medium": [], "low": []}
    for file, vuln_list in vulnerabilities.items():
        for vuln in vuln_list:
            severity = vuln.get("vuln_description", "").lower()
            if "critical" in severity or "high" in severity:
                categorized_vulnerabilities["high"].append(vuln)
            elif "medium" in severity:
                categorized_vulnerabilities["medium"].append(vuln)
            else:
                categorized_vulnerabilities["low"].append(vuln)
    return categorized_vulnerabilities

# SBOM Vulnerabilities
def get_sbom_vulnerabilities():
    sbom_vulnerabilities = defaultdict(list)
    sbom_results_path = 'sbom/test_code_grype_results.json'
    if os.path.exists(sbom_results_path):
        with open(sbom_results_path, 'r') as file:
            sbom_data = json.load(file)
            seen_vulnerabilities = set()
            for match in sbom_data["matches"]:
                package = match["artifact"]["name"]
                cve_id = match["vulnerability"]["id"]
                severity = match["vulnerability"]["severity"]
                fix_url = get_fix_url(cve_id)
                unique_key = (package, cve_id)
                if unique_key in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add(unique_key)
                vuln = {"package": package, "cve": cve_id, "severity": severity, "fix_url": fix_url}
                sbom_vulnerabilities[package].append(vuln)
    return sbom_vulnerabilities

# Categorize SBOM Vulnerabilities
def categorize_sbom_vulnerabilities(vulnerabilities):
    categorized_vulnerabilities = {"high": [], "medium": [], "low": []}
    for package, vuln_list in vulnerabilities.items():
        for vuln in vuln_list:
            severity = vuln.get("severity", "").lower()
            if severity == "high":
                categorized_vulnerabilities["high"].append(vuln)
            elif severity == "medium":
                categorized_vulnerabilities["medium"].append(vuln)
            else:
                categorized_vulnerabilities["low"].append(vuln)
    return categorized_vulnerabilities

@app.route('/')
def dashboard():
    codeql_vulns = get_codeql_vulnerabilities()
    sbom_vulns = get_sbom_vulnerabilities()
    categorized_codeql_vulns = categorize_codeql_vulnerabilities(codeql_vulns)
    categorized_sbom_vulns = categorize_sbom_vulnerabilities(sbom_vulns)
    return render_template(
        'dashboard.html',
        codeql_categorized_vulns=categorized_codeql_vulns,
        sbom_categorized_vulns=categorized_sbom_vulns
    )

@app.route('/codeql-details')
def codeql_details():
    return render_template('codeql_details.html', codeql_vulnerabilities=get_codeql_vulnerabilities())

@app.route('/sbom-details')
def sbom_details():
    return render_template('sbom_details.html', sbom_vulnerabilities=get_sbom_vulnerabilities())

def main(argv):
    global source_root
    if '-h' in argv or '--help' in argv:
        help()
        sys.exit()
    if '-s' not in argv:
        print("Missing argument: -s or --source-root")
        sys.exit()
    source_root = argv[argv.index('-s') + 1]
    languages = ['python', 'java', 'javascript']
    if '-a' in argv or '--analyze' in argv:
        codeql_analyze(source_root, languages)
    if '-sbom' in argv:
        sbom_analyze(source_root)
    if '-g' in argv or '--guideline' in argv:
        app.run(debug=True)

if __name__ == "__main__":
    main(sys.argv[1:])
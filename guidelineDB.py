import os
import subprocess
import csv
import json
import sys
import sqlite3
from flask import Flask, render_template

app = Flask(__name__)

def help():
    print('Usage: guidelineDB.py <command> <argument>...')
    print('Command options:')
    print('\t-h, --help\t\tShow this help text.')
    print('\t-s, --source-root\tInput your project source directory name.')
    print('\t-a, --analyze\t\tRun CodeQL analysis.')
    print('\t-sbom\t\t\tRun SBOM generation and vulnerability analysis.')
    print('\t-g, --guideline\t\tShow analysis results and generate secure coding guidelines.')

def codeql_analyze(source_root, languages):
    # 각 언어별 CodeQL 분석 수행
    for language in languages:
        os.makedirs(f'codeql-db/{language}', exist_ok=True)
        
        # 언어별 쿼리 경로 설정
        query_paths = {
            'python': 'codeql-repo/python/ql/src/Security',
            'java': 'codeql-repo/java/ql/src/Security',
            'javascript': 'codeql-repo/javascript/ql/src/Security',
            'go': 'codeql-repo/go/ql/src/Security'
        }
        
        if language not in query_paths:
            raise ValueError(f"Unsupported language: {language}")
        
        # CodeQL 데이터베이스 생성
        subprocess.run([
            'codeql', 'database', 'create', f'codeql-db/{language}/{source_root}',
            '--language=' + language, '--source-root', source_root, '--overwrite'
        ], check=True)

        # 결과 디렉토리 생성
        os.makedirs(f'results/{language}', exist_ok=True)

        # CodeQL 분석 및 결과 저장
        subprocess.run([
            'codeql', 'database', 'analyze', f'codeql-db/{language}/{source_root}',
            query_paths[language],  # 언어별 쿼리 경로 선택
            '--format=csv', '--output', f'results/{language}/results.csv'
        ], check=True)

def sbom_analyze(source_root):
    os.makedirs('sbom', exist_ok=True)
    sbom_path = f'sbom/{source_root}_sbom.json'

    # Syft 명령 실행 (디렉토리 전체를 대상으로 SBOM 생성)
    subprocess.run(['syft', f'dir:{source_root}', '-o', f'json={sbom_path}'], check=True)

    sbom_results_path = f'sbom/{source_root}_grype_results.json'

    # Grype 명령 실행
    subprocess.run(['grype', f'sbom:{sbom_path}', '-o', f'json={sbom_results_path}'], check=True)

def get_guideline_url(cwe_id):
    conn = sqlite3.connect("securecoding_guideline.db")
    cur = conn.cursor()
    cur.execute("SELECT guideline FROM guidelineDB WHERE vuln_name = ?", (cwe_id,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else "No guideline available"

def get_fix_url(cve_id):
    # CVE ID에 따라 취약점 해결 URL 생성
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

@app.route('/')
def display_results():
    # 여러 언어에 대한 CodeQL 결과 처리
    codeql_vulnerabilities = []
    languages = ['python', 'java', 'javascript', 'go']
    
    for language in languages:
        codeql_results_path = f'results/{language}/results.csv'
        with open(codeql_results_path, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 6:
                    cwe_id = row[0].split(" ")[0]  # 예: "CWE-79" 형태로 추출
                    guideline_url = get_guideline_url(cwe_id)
                    codeql_vulnerabilities.append({
                        "vuln_name": row[0],
                        "vuln_description": row[1],
                        "file": row[4],
                        "line": row[5],
                        "cwe_id": cwe_id,
                        "guideline_url": guideline_url,
                        "language": language  # 언어 추가
                    })

    # Parse SBOM Results
    sbom_results_path = 'sbom/test_code_grype_results.json'
    sbom_vulnerabilities = []
    with open(sbom_results_path, 'r') as file:
        sbom_data = json.load(file)
        sbom_vulnerabilities = [
            {
                "package": match["artifact"]["name"],
                "cve": match["vulnerability"]["id"],
                "severity": match["vulnerability"]["severity"],
                "fix_url": get_fix_url(match["vulnerability"]["id"]),
            }
            for match in sbom_data["matches"]
        ]

    return render_template('results.html',
                           codeql_vulnerabilities=codeql_vulnerabilities,
                           sbom_vulnerabilities=sbom_vulnerabilities)

def main(argv):
    if '-h' in argv or '--help' in argv:
        help()
        sys.exit()

    if '-s' not in argv:
        print("Missing argument: -s or --source-root")
        sys.exit()

    source_root = argv[argv.index('-s') + 1]
    languages = ['python', 'java', 'javascript', 'go']  # 예시로 여러 언어 지원

    if '-a' in argv or '--analyze' in argv:
        codeql_analyze(source_root, languages)

    if '-sbom' in argv:
        sbom_analyze(source_root)

    if '-g' in argv or '--guideline' in argv:
        app.run()

if __name__ == "__main__":
    main(sys.argv[1:])

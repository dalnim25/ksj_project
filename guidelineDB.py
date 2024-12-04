import os
import subprocess
import json
import sys
import sqlite3
from flask import Flask, render_template

app = Flask(__name__)

# 소스 루트 디렉토리를 앱 전역에서 사용할 수 있도록 설정
source_root = ""  # 기본값으로 빈 문자열 설정

def help():
    print('Usage: guidelineDB.py <command> <argument>...')
    print('Command options:')
    print('\t-h, --help\t\tShow this help text.')
    print('\t-s, --source-root\tInput your project source directory name.')
    print('\t-a, --analyze\t\tRun CodeQL analysis.')
    print('\t-sbom\t\t\tRun SBOM generation and vulnerability analysis.')
    print('\t-g, --guideline\t\tShow analysis results and generate secure coding guidelines.')

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

        # 이전 분석 결과가 있다면 삭제
        result_path = f'results/{language}/results.sarif'
        if os.path.exists(result_path):
            os.remove(result_path)

        # CodeQL 분석 실행
        subprocess.run([
            'codeql', 'database', 'create', f'codeql-db/{language}/{source_root}',
            '--language=' + language, '--source-root', source_root, '--overwrite'
        ], check=True)

        os.makedirs(f'results/{language}', exist_ok=True)

        # 새로 분석하여 결과 저장
        subprocess.run([
            'codeql', 'database', 'analyze', f'codeql-db/{language}/{source_root}',
            query_paths[language], '--format=sarif-latest', '--output', result_path
        ], check=True)

def sbom_analyze(source_root):
    os.makedirs('sbom', exist_ok=True)

    # 이전 SBOM 결과가 있으면 삭제
    sbom_path = f'sbom/{source_root}_sbom.json'
    if os.path.exists(sbom_path):
        os.remove(sbom_path)
        
    sbom_results_path = f'sbom/{source_root}_grype_results.json'
    if os.path.exists(sbom_results_path):
        os.remove(sbom_results_path)

    # SBOM 파일 생성
    subprocess.run(['syft', f'dir:{source_root}', '-o', f'json={sbom_path}'], check=True)

    # SBOM 취약점 분석
    subprocess.run(['grype', f'sbom:{sbom_path}', '-o', f'json={sbom_results_path}'], check=True)

def get_guideline_url(cwe_id):
    conn = sqlite3.connect("securecoding_guideline.db")
    cur = conn.cursor()

    # 입력값 정규화: 소문자 변환 + 하이픈과 공백 제거
    normalized_cwe_id = cwe_id.replace("js/", "").replace("java/", "").replace("py/", "").replace("-", "").replace(" ", "").strip().lower()
    print(f"Normalized CWE ID for DB search: {normalized_cwe_id}")

    # 데이터베이스 검색
    cur.execute("SELECT guideline FROM vulnerabilities WHERE vuln_name = ?", (normalized_cwe_id,))
    result = cur.fetchone()

    conn.close()

    if result:
        print(f"Found guideline: {result[0]}")
        return result[0]
    else:
        print(f"No guideline found for: {normalized_cwe_id}")
        return "No guideline available"


def get_fix_url(cve_id):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

@app.route('/')
def display_results():
    global source_root  # 전역 변수로 source_root 사용

    codeql_vulnerabilities = []
    languages = ['python', 'java', 'javascript']
    
    for language in languages:
        codeql_results_path = f'results/{language}/results.sarif'  
        if not os.path.exists(codeql_results_path):
            continue  

        with open(codeql_results_path, 'r') as file:
            data = json.load(file)  
            for result in data['runs'][0]['results']:
                cwe_id = result.get('ruleId', 'Unknown')  
                if 'properties' in result:
                    cwe_id = result['properties'].get('cwe', cwe_id)

                guideline_url = get_guideline_url(cwe_id)

                # 취약점 정보 저장
                vuln = {
                    "vuln_name": result.get('message', {}).get('text', 'N/A'),
                    "vuln_description": result.get('message', {}).get('text', 'N/A'),
                    "file": result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'N/A'),
                    "line": result.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine', 'N/A'),
                    "cwe_id": cwe_id,  
                    "guideline_url": guideline_url,
                    "language": language,
                    "code": get_code_from_file(result.get('locations', [{}])[0].get('physicalLocation', {}).get('artifactLocation', {}).get('uri', 'N/A'), result.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine', 'N/A'), source_root)  # 상대경로로 코드 읽기
                }

                if vuln not in codeql_vulnerabilities:
                    codeql_vulnerabilities.append(vuln)

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

def get_code_from_file(file_path, line_number, source_root):
    try:
        # 소스 루트 디렉토리와 결합하여 상대 경로를 처리
        abs_file_path = os.path.join(source_root, file_path.lstrip('/'))  # 상대 경로를 절대 경로로 변환
        print(f"Reading file: {abs_file_path}")  # 디버깅 용도, 확인할 경로 출력
        
        with open(abs_file_path, 'r') as f:
            lines = f.readlines()
            return lines[int(line_number) - 1]  # 1-based line number to 0-based index
    except Exception as e:
        print(f"Error: {e}")
        return f"Error reading file: {e}"

def main(argv):
    global source_root  # 전역 변수로 source_root 설정

    if '-h' in argv or '--help' in argv:
        help()
        sys.exit()

    if '-s' not in argv:
        print("Missing argument: -s or --source-root")
        sys.exit()

    source_root = argv[argv.index('-s') + 1]
    #languages = ['python', 'java', 'javascript']  
    languages = ['python','java','javascript'] 

    if '-a' in argv or '--analyze' in argv:
        codeql_analyze(source_root, languages)

    if '-sbom' in argv:
        sbom_analyze(source_root)

    if '-g' in argv or '--guideline' in argv:
        app.run()

if __name__ == "__main__":
    main(sys.argv[1:])

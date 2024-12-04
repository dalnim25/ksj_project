import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sqlite3

# 1. 크롤링할 URL
base_url = "https://codeql.github.com/codeql-query-help/java/"
response = requests.get(base_url)
soup = BeautifulSoup(response.text, "html.parser")

# 2. vuln_name을 정규화 (언어 접두사 제거)
def normalize_vuln_name(href):
    try:
        # href 속성에서 URL 끝 부분 추출
        vuln_name = href.split("/")[-2]  # URL 끝 부분 추출
        if "-" in vuln_name:
            return "-".join(vuln_name.split("-")[1:])  # 첫 번째 접두사 제거
        return vuln_name
    except IndexError:
        # href가 잘못된 경우 기본값 반환
        return "unknown"

# 3. 데이터 리스트 생성
data_list = []
for link in soup.select("li.toctree-l1 > a.reference.internal"):
    href = link.get("href", "")  # href 속성 가져오기, 없으면 빈 문자열
    if not href:
        continue  # href가 없는 경우 건너뜀
    vuln_name = normalize_vuln_name(href)  # 언어 접두사 제거 후 정규화된 vuln_name
    guideline_url = urljoin(base_url, href)  # 절대 경로 URL 생성
    data_list.append(("java", vuln_name, guideline_url))

# 4. SQLite3 데이터베이스 연결 및 저장
db_name = "securecoding_guideline.db"
connection = sqlite3.connect(db_name)

try:
    # 테이블 생성
    with connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_lang TEXT,
                vuln_name TEXT,
                guideline TEXT
            )
        """)

    # 데이터 삽입
    with connection:
        connection.executemany(
            "INSERT INTO vulnerabilities (vuln_lang, vuln_name, guideline) VALUES (?, ?, ?)",
            data_list
        )
    print("데이터 저장 완료! SQLite3에 저장되었습니다.")

finally:
    connection.close()

# 5. 데이터 확인
connection = sqlite3.connect(db_name)
cursor = connection.cursor()
cursor.execute("SELECT * FROM vulnerabilities")
rows = cursor.fetchall()

for row in rows:
    print(row)

connection.close()

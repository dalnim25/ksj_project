import requests
from bs4 import BeautifulSoup
import sqlite3

conn = sqlite3.connect("securecoding_guideline.db")
cur = conn.cursor()

# 데이터베이스에 저장된 vuln_name 값 출력
cur.execute("SELECT vuln_name FROM vulnerabilities")
rows = cur.fetchall()

for row in rows:
    print(f"Database vuln_name: {row[0]}")  # vuln_name 값 출력

conn.close()


# import sqlite3

# def normalize_vuln_names():
#     db_name = "securecoding_guideline.db"
#     connection = sqlite3.connect(db_name)
#     cursor = connection.cursor()

#     try:
#         # 1. 모든 vuln_name 값 가져오기
#         cursor.execute("SELECT id, vuln_name FROM vulnerabilities")
#         rows = cursor.fetchall()

#         # 2. 정규화된 vuln_name 생성
#         updates = []
#         for row in rows:
#             vuln_id = row[0]
#             original_name = row[1]
#             # 공백 제거, 하이픈 제거, 소문자 변환
#             normalized_name = original_name.replace(" ", "").replace("-", "").strip().lower()
#             updates.append((normalized_name, vuln_id))

#         # 3. 데이터베이스 업데이트
#         for normalized_name, vuln_id in updates:
#             cursor.execute(
#                 "UPDATE vulnerabilities SET vuln_name = ? WHERE id = ?",
#                 (normalized_name, vuln_id)
#             )

#         connection.commit()
#         print(f"{len(updates)}개의 vuln_name이 정규화되었습니다.")

#     except Exception as e:
#         print(f"오류 발생: {e}")
#     finally:
#         connection.close()

# # 정규화 실행
# normalize_vuln_names()

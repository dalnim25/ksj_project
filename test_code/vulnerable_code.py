import sqlite3

def vulnerable_query(user_input):
    # SQL Injection 취약점
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

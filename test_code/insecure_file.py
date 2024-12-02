import os

def insecure_file_access(file_name):
    # Path Traversal 취약점
    with open(f"/data/{file_name}", "r") as f:
        return f.read()

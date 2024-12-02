from flask import Flask, request

app = Flask(__name__)

@app.route("/unsafe")
def unsafe():
    # Cross-site Scripting (XSS) 취약점
    name = request.args.get("name", "")
    return f"<h1>Hello, {name}</h1>"

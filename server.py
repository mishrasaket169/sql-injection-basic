from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).parent
DATABASE = ROOT / "demo.db"


def initialize_database():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
            ("demo", "password123"),
        )
        connection.commit()


def safe_login(username, password):
    """Safe example: values are bound as parameters, never joined into SQL."""
    with sqlite3.connect(DATABASE) as connection:
        row = connection.execute(
            "SELECT username FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
    return row is not None, "Parameterized query rejected the input safely."


def vulnerable_login(username, password):
    """Intentionally unsafe example for local security lab testing only."""
    query = (
        "SELECT username FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    try:
        with sqlite3.connect(DATABASE) as connection:
            row = connection.execute(query).fetchone()
        return row is not None, "The concatenated SQL query returned a user."
    except sqlite3.Error:
        return False, "The injected SQL was invalid and the query failed."


class LoginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_file("index.html", "text/html; charset=utf-8")
            return
        if self.path == "/styles.css":
            self.send_file("styles.css", "text/css; charset=utf-8")
            return
        self.send_error(404)

    def do_POST(self):
        if self.path not in ("/api/login/safe", "/api/login/vulnerable"):
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        if self.path.endswith("/safe"):
            authenticated, detail = safe_login(username, password)
            mode = "safe"
        else:
            authenticated, detail = vulnerable_login(username, password)
            mode = "vulnerable"

        self.send_json(
            {
                "authenticated": authenticated,
                "mode": mode,
                "detail": detail,
                "message": "Access granted" if authenticated else "Access denied",
            }
        )

    def send_file(self, filename, content_type):
        content = (ROOT / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, payload):
        content = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")


if __name__ == "__main__":
    initialize_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), LoginHandler)
    print("SQL injection lab running at http://127.0.0.1:8000")
    server.serve_forever()

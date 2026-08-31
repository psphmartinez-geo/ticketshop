"""
TicketShop - sistema simple de compra de boletos online.

⚠️ Este proyecto contiene vulnerabilidades INTRODUCIDAS A PROPÓSITO
con fines educativos (demo de Semgrep / AppSec). No usar en producción.

Cada punto vulnerable está marcado con el comentario "# VULNERABLE:"
para que sea fácil de encontrar cuando prepares la clase.
"""

import base64
import hashlib
import os
import pickle
import sqlite3

import requests
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
)

app = Flask(__name__)

# VULNERABLE: secret key hardcodeada en el código fuente
app.secret_key = "supersecretkey123"

# VULNERABLE: API key hardcodeada (simula credencial de pasarela de pago)
PAYMENT_API_KEY = "sk_live_4242424242424242"

DB_PATH = os.path.join(os.path.dirname(__file__), "tickets.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            venue TEXT,
            price REAL
        );
        """
    )
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        # VULNERABLE: hashing débil (MD5) para contraseñas
        pw = hashlib.md5("admin123".encode()).hexdigest()
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", ("admin", pw)
        )
        conn.execute(
            "INSERT INTO events (name, venue, price) VALUES (?, ?, ?)",
            ("Concierto Rock Fest", "Estadio Central", 350.0),
        )
        conn.execute(
            "INSERT INTO events (name, venue, price) VALUES (?, ?, ?)",
            ("Teatro: Hamlet", "Sala Nacional", 180.0),
        )
        conn.commit()
    conn.close()


@app.route("/")
def index():
    conn = get_db()
    events = conn.execute("SELECT * FROM events").fetchall()
    conn.close()
    return render_template("index.html", events=events)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    # VULNERABLE: SQL Injection - concatenación directa de input del usuario
    query = "SELECT * FROM events WHERE name LIKE '%" + q + "%'"
    cur = conn.execute(query)
    results = cur.fetchall()
    conn.close()

    # VULNERABLE: XSS reflejado - el input del usuario se inyecta en el HTML
    # y se renderiza con render_template_string sin escapar
    html = "<h2>Resultados para: " + q + "</h2>{% for e in results %}<p>{{ e['name'] }}</p>{% endfor %}"
    return render_template_string(html, results=results)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        # VULNERABLE: SQL Injection en el formulario de login (f-string)
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{pw_hash}'"
        )
        user = conn.execute(query).fetchone()
        conn.close()
        if user:
            session["user"] = username
            # VULNERABLE: Open Redirect - redirige a cualquier URL indicada por el usuario
            next_url = request.args.get("next", "/")
            return redirect(next_url)
        return "Credenciales inválidas", 401
    return render_template("login.html")


@app.route("/cart", methods=["POST"])
def cart():
    # VULNERABLE: Deserialización insegura - pickle sobre datos del usuario
    raw = request.form.get("cart_data", "")
    data = pickle.loads(base64.b64decode(raw))
    return jsonify({"items": data})


@app.route("/ticket/<path:filename>")
def get_ticket(filename):
    # VULNERABLE: Path Traversal - no se valida ni sanitiza el filename
    filepath = os.path.join("tickets", filename)
    return send_file(filepath)


@app.route("/generate-ticket", methods=["POST"])
def generate_ticket():
    event_name = request.form.get("event_name", "")
    # VULNERABLE: Command Injection - input del usuario pasado al shell
    cmd = f"echo 'Boleto para: {event_name}' > tickets/output.txt"
    os.system(cmd)
    return "Boleto generado"


@app.route("/payment/callback", methods=["POST"])
def payment_callback():
    webhook_url = request.form.get("callback_url", "")
    # VULNERABLE: SSRF - el servidor hace una petición a una URL controlada por el usuario
    resp = requests.get(webhook_url)
    return resp.text


@app.after_request
def add_cors_headers(response):
    # VULNERABLE: CORS mal configurado (wildcard + credentials)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    init_db()
    os.makedirs("tickets", exist_ok=True)
    # VULNERABLE: modo debug habilitado (expone Werkzeug debugger / RCE)
    app.run(host="0.0.0.0", port=5000, debug=True)

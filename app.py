--- app_before.py	2026-08-31 17:55:33.220304315 +0000
+++ app.py	2026-08-31 17:56:01.656306005 +0000
@@ -1,40 +1,46 @@
 """
 TicketShop - sistema simple de compra de boletos online.
 
-⚠️ Este proyecto contiene vulnerabilidades INTRODUCIDAS A PROPÓSITO
-con fines educativos (demo de Semgrep / AppSec). No usar en producción.
-
-Cada punto vulnerable está marcado con el comentario "# VULNERABLE:"
-para que sea fácil de encontrar cuando prepares la clase.
+Version CORREGIDA - cada fix está comentado con "# FIX:" y referencia
+al problema original, para comparar en clase contra app_before.py.
 """
 
-import base64
-import hashlib
+import ipaddress
 import os
-import pickle
+import socket
 import sqlite3
+from urllib.parse import urljoin, urlparse
 
 import requests
 from flask import (
     Flask,
+    abort,
     jsonify,
     redirect,
     render_template,
-    render_template_string,
     request,
     send_file,
     session,
 )
+from werkzeug.security import check_password_hash, generate_password_hash
+from werkzeug.utils import secure_filename
 
 app = Flask(__name__)
 
-# VULNERABLE: secret key hardcodeada en el código fuente
-app.secret_key = "supersecretkey123"
+# FIX: secret key ya no está hardcodeada, se toma de una variable de entorno.
+# En local: export FLASK_SECRET_KEY="algo-largo-y-aleatorio"
+app.secret_key = os.environ.get("FLASK_SECRET_KEY")
+if not app.secret_key:
+    raise RuntimeError("Falta definir FLASK_SECRET_KEY en el entorno")
 
-# VULNERABLE: API key hardcodeada (simula credencial de pasarela de pago)
-PAYMENT_API_KEY = "sk_live_4242424242424242"
+# FIX: API key también se lee del entorno, nunca del código fuente.
+PAYMENT_API_KEY = os.environ.get("PAYMENT_API_KEY", "")
 
 DB_PATH = os.path.join(os.path.dirname(__file__), "tickets.db")
+TICKETS_DIR = os.path.join(os.path.dirname(__file__), "tickets")
+
+# FIX: allowlist explícita de hosts permitidos para el callback de pago (mitiga SSRF)
+ALLOWED_CALLBACK_HOSTS = {"payments.example.com"}
 
 
 def get_db():
@@ -63,8 +69,8 @@
     cur = conn.cursor()
     cur.execute("SELECT COUNT(*) FROM users")
     if cur.fetchone()[0] == 0:
-        # VULNERABLE: hashing débil (MD5) para contraseñas
-        pw = hashlib.md5("admin123".encode()).hexdigest()
+        # FIX: hashing fuerte con salt (PBKDF2 vía werkzeug) en vez de MD5.
+        pw = generate_password_hash("admin123")
         conn.execute(
             "INSERT INTO users (username, password) VALUES (?, ?)", ("admin", pw)
         )
@@ -92,16 +98,15 @@
 def search():
     q = request.args.get("q", "")
     conn = get_db()
-    # VULNERABLE: SQL Injection - concatenación directa de input del usuario
-    query = "SELECT * FROM events WHERE name LIKE '%" + q + "%'"
-    cur = conn.execute(query)
+    # FIX: SQL Injection resuelto con consulta parametrizada (placeholder ?)
+    query = "SELECT * FROM events WHERE name LIKE ?"
+    cur = conn.execute(query, (f"%{q}%",))
     results = cur.fetchall()
     conn.close()
 
-    # VULNERABLE: XSS reflejado - el input del usuario se inyecta en el HTML
-    # y se renderiza con render_template_string sin escapar
-    html = "<h2>Resultados para: " + q + "</h2>{% for e in results %}<p>{{ e['name'] }}</p>{% endfor %}"
-    return render_template_string(html, results=results)
+    # FIX: XSS resuelto usando render_template (autoescape de Jinja2) en vez
+    # de construir HTML a mano con render_template_string.
+    return render_template("search.html", q=q, results=results)
 
 
 @app.route("/login", methods=["GET", "POST"])
@@ -110,65 +115,110 @@
         username = request.form.get("username", "")
         password = request.form.get("password", "")
         conn = get_db()
-        pw_hash = hashlib.md5(password.encode()).hexdigest()
-        # VULNERABLE: SQL Injection en el formulario de login (f-string)
-        query = (
-            f"SELECT * FROM users WHERE username = '{username}' "
-            f"AND password = '{pw_hash}'"
-        )
-        user = conn.execute(query).fetchone()
+        # FIX: SQL Injection resuelto con consulta parametrizada
+        user = conn.execute(
+            "SELECT * FROM users WHERE username = ?", (username,)
+        ).fetchone()
         conn.close()
-        if user:
+        # FIX: verificación de password con hash+salt (constante en tiempo)
+        if user and check_password_hash(user["password"], password):
             session["user"] = username
-            # VULNERABLE: Open Redirect - redirige a cualquier URL indicada por el usuario
+            # FIX: Open Redirect resuelto - solo se permite redirigir a una
+            # ruta relativa dentro del propio sitio, nunca a un host externo.
             next_url = request.args.get("next", "/")
+            if not _is_safe_local_path(next_url):
+                next_url = "/"
             return redirect(next_url)
         return "Credenciales inválidas", 401
     return render_template("login.html")
 
 
+def _is_safe_local_path(path: str) -> bool:
+    """Solo permite rutas relativas locales (sin esquema ni host)."""
+    if not path.startswith("/"):
+        return False
+    parsed = urlparse(urljoin(request.host_url, path))
+    return parsed.netloc == urlparse(request.host_url).netloc
+
+
 @app.route("/cart", methods=["POST"])
 def cart():
-    # VULNERABLE: Deserialización insegura - pickle sobre datos del usuario
-    raw = request.form.get("cart_data", "")
-    data = pickle.loads(base64.b64decode(raw))
-    return jsonify({"items": data})
+    # FIX: Deserialización insegura resuelta - se usa JSON en vez de pickle,
+    # que no puede ejecutar código arbitrario al deserializar.
+    data = request.get_json(silent=True) or {}
+    items = data.get("items", [])
+    if not isinstance(items, list):
+        abort(400)
+    return jsonify({"items": items})
 
 
 @app.route("/ticket/<path:filename>")
 def get_ticket(filename):
-    # VULNERABLE: Path Traversal - no se valida ni sanitiza el filename
-    filepath = os.path.join("tickets", filename)
+    # FIX: Path Traversal resuelto - se sanitiza el nombre y se valida que
+    # la ruta final quede dentro de TICKETS_DIR.
+    safe_name = secure_filename(filename)
+    filepath = os.path.normpath(os.path.join(TICKETS_DIR, safe_name))
+    if not filepath.startswith(os.path.normpath(TICKETS_DIR) + os.sep):
+        abort(400)
+    if not os.path.isfile(filepath):
+        abort(404)
     return send_file(filepath)
 
 
 @app.route("/generate-ticket", methods=["POST"])
 def generate_ticket():
     event_name = request.form.get("event_name", "")
-    # VULNERABLE: Command Injection - input del usuario pasado al shell
-    cmd = f"echo 'Boleto para: {event_name}' > tickets/output.txt"
-    os.system(cmd)
+    # FIX: Command Injection resuelto - se escribe el archivo directamente
+    # desde Python, sin invocar una shell con input del usuario.
+    os.makedirs(TICKETS_DIR, exist_ok=True)
+    output_path = os.path.join(TICKETS_DIR, "output.txt")
+    with open(output_path, "a", encoding="utf-8") as f:
+        f.write(f"Boleto para: {event_name}\n")
     return "Boleto generado"
 
 
 @app.route("/payment/callback", methods=["POST"])
 def payment_callback():
     webhook_url = request.form.get("callback_url", "")
-    # VULNERABLE: SSRF - el servidor hace una petición a una URL controlada por el usuario
-    resp = requests.get(webhook_url)
+    # FIX: SSRF mitigado - se valida esquema https, host en allowlist, y que
+    # no resuelva a IPs privadas/loopback antes de hacer la petición.
+    if not _is_allowed_callback_url(webhook_url):
+        abort(400, "URL de callback no permitida")
+    resp = requests.get(webhook_url, timeout=5)
     return resp.text
 
 
+def _is_allowed_callback_url(url: str) -> bool:
+    parsed = urlparse(url)
+    if parsed.scheme != "https":
+        return False
+    if parsed.hostname not in ALLOWED_CALLBACK_HOSTS:
+        return False
+    try:
+        resolved_ip = socket.gethostbyname(parsed.hostname)
+        ip_obj = ipaddress.ip_address(resolved_ip)
+        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
+            return False
+    except (socket.gaierror, ValueError):
+        return False
+    return True
+
+
 @app.after_request
 def add_cors_headers(response):
-    # VULNERABLE: CORS mal configurado (wildcard + credentials)
-    response.headers["Access-Control-Allow-Origin"] = "*"
-    response.headers["Access-Control-Allow-Credentials"] = "true"
+    # FIX: CORS restringido a un origen específico en vez de wildcard "*",
+    # que además es incompatible con Allow-Credentials por spec.
+    allowed_origin = os.environ.get("ALLOWED_ORIGIN", "https://ticketshop.example.com")
+    origin = request.headers.get("Origin")
+    if origin == allowed_origin:
+        response.headers["Access-Control-Allow-Origin"] = allowed_origin
+        response.headers["Access-Control-Allow-Credentials"] = "true"
     return response
 
 
 if __name__ == "__main__":
     init_db()
-    os.makedirs("tickets", exist_ok=True)
-    # VULNERABLE: modo debug habilitado (expone Werkzeug debugger / RCE)
-    app.run(host="0.0.0.0", port=5000, debug=True)
+    os.makedirs(TICKETS_DIR, exist_ok=True)
+    # FIX: debug controlado por variable de entorno, apagado por defecto.
+    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
+    app.run(host="127.0.0.1", port=5000, debug=debug_mode)

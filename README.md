# TicketShop 🎟️ (repo vulnerable para clase de Semgrep AppSec)

App Flask muy simple que simula un sistema de compra de boletos online.
Contiene vulnerabilidades **introducidas a propósito** para ser detectadas
por Semgrep en vivo y corregidas durante la clase.

> ⚠️ No desplegar en producción ni exponer a internet. Es material didáctico.

## Requisitos

- Python 3.10+
- `pip install -r requirements.txt`
- `pip install semgrep` (para correrlo en local)

## Correr la app localmente

```bash
pip install -r requirements.txt
python app.py
```

Abre http://localhost:5000

## Correr Semgrep en local

```bash
./run_semgrep.sh
```

Esto usa los rulesets públicos:
- `p/owasp-top-ten`
- `p/security-audit`
- `p/python`
- `p/flask`

El mismo análisis corre en CI vía GitHub Actions (`.github/workflows/semgrep.yml`),
con `--error` para que el job falle si hay hallazgos — ideal para mostrar
un pipeline que bloquea el merge hasta corregir.

## Cómo subirlo a GitHub

```bash
cd ticketshop
git init
git add .
git commit -m "Initial commit: TicketShop (vulnerable on purpose)"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/ticketshop.git
git push -u origin main
```

Con el push, el workflow de Actions se dispara solo y vas a ver los
hallazgos de Semgrep en la pestaña **Security > Code scanning alerts**
(gracias al `upload-sarif`), además del log del job.

## Flujo sugerido para la clase

1. **Mostrar el repo limpio** (sin decir dónde están los bugs) y correr
   `semgrep scan --config auto` o el `run_semgrep.sh` para que el grupo
   vea la lista de hallazgos generada automáticamente.
2. **Triage en vivo**: agrupar hallazgos por severidad/CWE, explicar cada
   patrón (concatenación en queries, `pickle.loads`, `os.system`, etc.).
3. **Arreglar 2–3 vulnerabilidades en vivo** (recomendado empezar por
   SQL Injection y Command Injection, son las más ilustrativas).
4. **Volver a correr Semgrep** (local o re-disparando el workflow con un
   nuevo commit/push) y mostrar cómo bajan los hallazgos.
5. Opcional: agregar un `.semgrep.yml` con una regla custom simple para
   mostrar cómo escribir reglas propias.

## Chuleta del instructor: vulnerabilidades incluidas

Cada una está marcada en el código con `# VULNERABLE:` para que las
ubiques rápido. Recomendado quitar los comentarios (o usar una rama
"limpia" sin comentarios) si no quieres dar la respuesta antes de tiempo.

| # | Vulnerabilidad | Archivo / función | CWE aprox. |
|---|---|---|---|
| 1 | SQL Injection (concatenación) | `app.py` → `search()` | CWE-89 |
| 2 | SQL Injection (f-string) | `app.py` → `login()` | CWE-89 |
| 3 | XSS reflejado vía `render_template_string` | `app.py` → `search()` | CWE-79 |
| 4 | Deserialización insegura (`pickle.loads`) | `app.py` → `cart()` | CWE-502 |
| 5 | Path Traversal (`send_file` sin validar) | `app.py` → `get_ticket()` | CWE-22 |
| 6 | Command Injection (`os.system` con f-string) | `app.py` → `generate_ticket()` | CWE-78 |
| 7 | SSRF (`requests.get` sobre URL del usuario) | `app.py` → `payment_callback()` | CWE-918 |
| 8 | Open Redirect | `app.py` → `login()` | CWE-601 |
| 9 | Hashing débil de contraseñas (MD5) | `app.py` → `init_db()`, `login()` | CWE-327 |
| 10 | Secret key hardcodeada | `app.py` (nivel módulo) | CWE-798 |
| 11 | API key hardcodeada | `app.py` (nivel módulo) | CWE-798 |
| 12 | CORS mal configurado (wildcard + credentials) | `app.py` → `add_cors_headers()` | CWE-942 |
| 13 | Modo debug habilitado (`debug=True`) | `app.py` → `if __name__ == "__main__"` | CWE-489 |

La mayoría de estos son detectados directamente por `p/owasp-top-ten` y
`p/security-audit`. El CORS wildcard y el open redirect a veces dependen
de la versión del ruleset; si alguno no aparece, es un buen gancho para
hablar de cobertura de reglas y cómo escribir una regla custom.

## Estructura

```
ticketshop/
├── app.py
├── requirements.txt
├── run_semgrep.sh
├── templates/
│   ├── index.html
│   └── login.html
├── tickets/
└── .github/workflows/semgrep.yml
```

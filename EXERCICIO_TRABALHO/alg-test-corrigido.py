# lab_mobile_backend_secure.py
# Versão revisada e ajustada com correções de segurança e organização.
# NOTA: Exemplo educativo. Em produção use HTTPS, stores persistentes (Redis/DB) e variáveis de ambiente para segredos.

import os
import json
import uuid
import time
import secrets
import mimetypes
from datetime import datetime
from pathlib import Path
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify, current_app, send_from_directory, abort, make_response
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------
# Configurações básicas
# ---------------------------
APP_DIR = Path(__file__).parent.resolve()
DATA_FILE = APP_DIR / "db_secure.json"
UPLOAD_FOLDER = APP_DIR / "uploads_secure"
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
TOKEN_EXP_SECONDS = 30 * 60  # 30 minutes
SECRET_KEY = os.getenv("LAB_SECRET_KEY", secrets.token_urlsafe(32))
ADMIN_GENERATE_KEY = os.getenv("ADMIN_GENERATE_KEY", None)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
try:
    os.chmod(UPLOAD_FOLDER, 0o700)
except Exception:
    pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = SECRET_KEY

# CORS: útil em laboratório. NÃO usar "*" em produção.
from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

# ---------------------------
# Stores em memória (apenas demo)
# ---------------------------
token_store = {}          # token -> {username, exp}
_rate_limits = defaultdict(lambda: {"count": 0, "reset": int(time.time()) + 60})
RATE_LIMIT_MAX = 60       # requests
RATE_LIMIT_WINDOW = 60    # seconds

# ---------------------------
# Helpers: DB & metadados
# ---------------------------
def read_db():
    """Lê o arquivo JSON com usuários e uploads. Se não existir, cria estrutura padrão."""
    if not DATA_FILE.exists():
        base = {"users": [], "uploads": []}
        write_db(base)
        return base
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception:
            # se arquivo corrompido, retornar estrutura vazia (não sobrescreve automaticamente)
            return {"users": [], "uploads": []}
    if "users" not in data:
        data["users"] = []
    if "uploads" not in data:
        data["uploads"] = []
    return data

def write_db(data):
    """Escreve dados no arquivo JSON (simples, legível)."""
    if "users" not in data:
        data["users"] = []
    if "uploads" not in data:
        data["uploads"] = []
    tmp = DATA_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(DATA_FILE)

def find_user(username):
    db = read_db()
    for u in db.get("users", []):
        if u.get("username") == username:
            return u
    return None

def save_user(user_obj):
    db = read_db()
    users = db.get("users", [])
    for i, u in enumerate(users):
        if u.get("username") == user_obj.get("username"):
            users[i] = user_obj
            db["users"] = users
            write_db(db)
            return
    users.append(user_obj)
    db["users"] = users
    write_db(db)

def save_upload_meta(meta_obj):
    """Salva metadados do upload no DB."""
    db = read_db()
    uploads = db.get("uploads", [])
    uploads.append(meta_obj)
    db["uploads"] = uploads
    write_db(db)

def find_upload(filename):
    """Retorna o metadado do upload pelo nome retornado (UUID.ext) ou None."""
    db = read_db()
    for u in db.get("uploads", []):
        if u.get("filename") == filename:
            return u
    return None

# ---------------------------
# Autenticação / tokens
# ---------------------------
def generate_token(username):
    token = secrets.token_urlsafe(32)
    exp = int(time.time()) + TOKEN_EXP_SECONDS
    token_store[token] = {"username": username, "exp": exp}
    return token, exp

def verify_token(token):
    entry = token_store.get(token)
    if not entry:
        return None
    if entry["exp"] < int(time.time()):
        token_store.pop(token, None)
        return None
    return entry["username"]

def revoke_token(token):
    token_store.pop(token, None)

def require_auth(require_admin=False):
    def decorator(f):
        @wraps(f)
        def inner(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "missing or invalid Authorization header"}), 401
            token = auth.split(" ", 1)[1].strip()
            username = verify_token(token)
            if not username:
                return jsonify({"error": "invalid or expired token"}), 401
            user = find_user(username)
            if not user:
                return jsonify({"error": "user not found"}), 401
            if require_admin and not user.get("is_admin"):
                return jsonify({"error": "forbidden - admin only"}), 403
            request.current_user = user
            request.current_token = token
            return f(*args, **kwargs)
        return inner
    return decorator

# ---------------------------
# Rate limiting simples (por IP)
# ---------------------------
def rate_limit(limit=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW):
    def decorator(f):
        @wraps(f)
        def inner(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            rec = _rate_limits[ip]
            now = int(time.time())
            if rec["reset"] <= now:
                rec["count"] = 0
                rec["reset"] = now + window
            rec["count"] += 1
            if rec["count"] > limit:
                return jsonify({"error": "rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return inner
    return decorator

# ---------------------------
# Utilitários uploads / validação
# ---------------------------
def allowed_file_extension(filename):
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS

def safe_mime_check(filename, file_stream):
    # Checagem básica por extensão; em produção use python-magic (libmagic) para inspecionar conteúdo.
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS

# ---------------------------
# Security headers
# ---------------------------
@app.after_request
def set_security_headers(response):
    # Não ative HSTS sem HTTPS; está comentado como referência
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    # CSP restritivo para demo (ajuste por necessidade)
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; object-src 'none';"
    return response

# ---------------------------
# Rotas públicas / seguras
# ---------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200

@app.route("/register", methods=["POST"])
@rate_limit()
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "missing username or password"}), 400
    if find_user(username):
        return jsonify({"error": "username already exists"}), 409
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    is_admin = bool(request.args.get("make_admin") == "1" and username == "admin")
    user_obj = {
        "username": username,
        "password_hash": pw_hash,
        "created_at": datetime.utcnow().isoformat(),
        "is_admin": is_admin
    }
    save_user(user_obj)
    return jsonify({"message": "user created", "username": username, "is_admin": is_admin}), 201

@app.route("/login", methods=["POST"])
@rate_limit()
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "missing username or password"}), 400
    user = find_user(username)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"error": "invalid credentials"}), 401
    token, exp = generate_token(username)
    return jsonify({
        "message": "login ok",
        "token_type": "Bearer",
        "token": token,
        "expires_at": datetime.utcfromtimestamp(exp).isoformat()
    }), 200

@app.route("/logout", methods=["POST"])
@require_auth(require_admin=False)
def logout():
    token = getattr(request, "current_token", None)
    if token:
        revoke_token(token)
    return jsonify({"message": "logged out"}), 200

@app.route("/generate_token", methods=["POST"])
@rate_limit()
def generate_token_endpoint():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "missing username"}), 400
    # Prefer admin Authorization
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        tok = auth.split(" ", 1)[1].strip()
        uname = verify_token(tok)
        if not uname:
            return jsonify({"error": "invalid or expired token"}), 401
        user = find_user(uname)
        if not user or not user.get("is_admin"):
            return jsonify({"error": "forbidden - admin only"}), 403
        if not find_user(username):
            return jsonify({"error": "user not found"}), 404
        t, exp = generate_token(username)
        return jsonify({"token": t, "username": username, "expires_at": datetime.utcfromtimestamp(exp).isoformat()}), 200
    # Fallback: ADMIN_GENERATE_KEY header (lab-only)
    header_key = request.headers.get("X-ADMIN-GENERATE-KEY", "")
    if ADMIN_GENERATE_KEY and header_key and header_key == ADMIN_GENERATE_KEY:
        if not find_user(username):
            return jsonify({"error": "user not found"}), 404
        t, exp = generate_token(username)
        return jsonify({"token": t, "username": username, "expires_at": datetime.utcfromtimestamp(exp).isoformat(), "note": "generated via ADMIN_GENERATE_KEY"}), 200
    return jsonify({"error": "unauthorized to generate token"}), 403

@app.route("/profile", methods=["GET"])
@require_auth(require_admin=False)
def profile():
    user = request.current_user
    safe = {"username": user.get("username"), "created_at": user.get("created_at"), "is_admin": user.get("is_admin", False)}
    return jsonify({"profile": safe}), 200

@app.route("/echo", methods=["POST"])
@require_auth(require_admin=False)
def echo():
    data = request.get_data(as_text=True)[:1024]
    safe = data.replace("<", "&lt;").replace(">", "&gt;")
    return current_app.response_class(f"Você enviou: {safe}", mimetype="text/plain")

@app.route("/upload", methods=["POST"])
@require_auth(require_admin=False)
@rate_limit()
def upload():
    current_user = request.current_user
    username = current_user.get("username")
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    f = request.files["file"]
    if not f or f.filename == "":
        return jsonify({"error": "no file selected"}), 400
    original_name = secure_filename(f.filename)
    if not allowed_file_extension(original_name):
        return jsonify({"error": "file type not allowed"}), 415
    if not safe_mime_check(original_name, f.stream):
        return jsonify({"error": "mimetype mismatch or not allowed"}), 415
    ext = Path(original_name).suffix.lower()
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOAD_FOLDER / safe_name
    try:
        f.save(dest)
    except Exception as e:
        return jsonify({"error": f"failed to save file: {e}"}), 500
    try:
        os.chmod(dest, 0o600)
    except Exception:
        pass
    meta = {
        "filename": dest.name,
        "original_name": original_name,
        "owner": username,
        "content_type": mimetypes.guess_type(original_name)[0] or "application/octet-stream",
        "created_at": datetime.utcnow().isoformat()
    }
    save_upload_meta(meta)
    return jsonify({"message": "uploaded", "path": str(dest.name)}), 201

@app.route("/uploads/<filename>", methods=["GET"])
@require_auth(require_admin=False)
def get_uploaded_file(filename):
    safe_name = secure_filename(filename)
    meta = find_upload(safe_name)
    requester = request.current_user
    requester_name = requester.get("username")
    is_admin = requester.get("is_admin", False)
    # se houver metadado, apenas owner ou admin podem acessar
    if meta:
        owner = meta.get("owner")
        if not (is_admin or requester_name == owner):
            return jsonify({"error": "forbidden - not owner or admin"}), 403
    else:
        # sem metadado: só admin pode acessar (não expor arquivos sem controle)
        if not is_admin:
            return jsonify({"error": "forbidden - file metadata missing; admin only"}), 403
    file_path = UPLOAD_FOLDER / safe_name
    if not file_path.exists():
        return jsonify({"error": "file not found"}), 404
    return send_from_directory(str(UPLOAD_FOLDER), safe_name, as_attachment=True)

@app.route("/user/uploads", methods=["GET"])
@require_auth(require_admin=False)
def user_list_uploads():
    current = request.current_user
    uname = current.get("username")
    db = read_db()
    user_uploads = [u for u in db.get("uploads", []) if u.get("owner") == uname]
    return jsonify({"uploads": user_uploads}), 200

@app.route("/admin/uploads", methods=["GET"])
@require_auth(require_admin=True)
def admin_list_uploads():
    db = read_db()
    return jsonify({"uploads": db.get("uploads", [])}), 200

@app.route("/admin/log", methods=["GET"])
@require_auth(require_admin=True)
def admin_log():
    db = read_db()
    masked = {"users": []}
    for u in db.get("users", []):
        masked["users"].append({"username": u.get("username"), "created_at": u.get("created_at"), "is_admin": u.get("is_admin", False)})
    return jsonify(masked), 200

@app.route("/list_uploads", methods=["GET"])
@require_auth(require_admin=False)
def list_uploads():
    """
    Lista uploads:
      - Sem parâmetro: retorna apenas os uploads do usuário atual.
      - Com ?all=1: retorna TODOS os uploads, mas SOMENTE para administradores.
    Regras extras:
      - Arquivos sem metadado só são listados para admin (nunca para usuário comum).
    """
    user = request.current_user
    is_admin = user.get("is_admin", False)
    username = user.get("username")

    # Se pedir todos, obrigatoriamente precisa ser admin
    want_all = request.args.get("all") == "1"
    if want_all and not is_admin:
        return jsonify({"error": "forbidden - only admin can list all uploads"}), 403

    db = read_db()
    meta_by_name = {m["filename"]: m for m in db.get("uploads", [])}

    results = []
    for file_path in UPLOAD_FOLDER.glob("*"):
        if not file_path.is_file():
            continue

        name = file_path.name
        meta = meta_by_name.get(name)

        if want_all:
            # Admin vendo tudo
            if meta:
                info = {
                    "filename": name,
                    "original_name": meta.get("original_name"),
                    "owner": meta.get("owner"),
                    "content_type": meta.get("content_type"),
                    "size_kb": round(file_path.stat().st_size / 1024, 2),
                    "created_at": meta.get("created_at"),
                }
            else:
                # Sem metadado: somente admin enxerga
                info = {
                    "filename": name,
                    "original_name": name,
                    "owner": None,
                    "content_type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                    "size_kb": round(file_path.stat().st_size / 1024, 2),
                    "created_at": datetime.utcfromtimestamp(file_path.stat().st_ctime).isoformat(),
                }
            results.append(info)
        else:
            # Usuário comum (ou admin sem all=1) → apenas seus próprios uploads
            if not meta:
                # Sem metadado: nunca mostrar para usuário comum
                # (admin também não vê sem all=1 para manter regra clara)
                continue
            if is_admin or meta.get("owner") == username:
                info = {
                    "filename": name,
                    "original_name": meta.get("original_name"),
                    "owner": meta.get("owner"),
                    "content_type": meta.get("content_type"),
                    "size_kb": round(file_path.stat().st_size / 1024, 2),
                    "created_at": meta.get("created_at"),
                }
                results.append(info)

    return jsonify({"uploads": results}), 200


# ---------------------------
# Execução local (apenas para laboratório)
# ---------------------------
if __name__ == "__main__":
    # debug=False para não vazar tracebacks sensíveis
    app.run(host="127.0.0.1", port=5000, debug=False)

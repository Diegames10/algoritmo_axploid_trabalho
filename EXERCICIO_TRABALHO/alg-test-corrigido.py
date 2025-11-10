# lab_mobile_backend_secure.py
# Versão segura do servidor didático (para substituição do lab inseguro)
# Comentários em português explicando a lógica e as razões de segurança.
# NOTA: Exemplo educativo. Em produção, use HTTPS, stores persistentes para tokens e variáveis de ambiente para segredos.

import os
import json
import uuid
import time
import secrets
import mimetypes
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, current_app, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------
# Configurações básicas
# ---------------------------
# Diretório do arquivo atual (útil para caminhos relativos)
APP_DIR = Path(__file__).parent.resolve()

# Arquivo JSON para armazenar usuários (demo). Em produção use um banco seguro.
DATA_FILE = APP_DIR / "db_secure.json"

# Pasta onde os uploads serão salvos (fora do webroot idealmente)
UPLOAD_FOLDER = APP_DIR / "uploads_secure"

# Extensões permitidas (whitelist) — evita permitir executáveis/HTML, etc.
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg"}

# Limite de tamanho máximo para uploads (5 MB)
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

# Tempo de expiração do token (em segundos) — 30 minutos aqui como exemplo
TOKEN_EXP_SECONDS = 30 * 60  # 30 minutes

# SECRET_KEY do Flask — em produção carregar de variável de ambiente
SECRET_KEY = os.getenv("LAB_SECRET_KEY", secrets.token_urlsafe(32))

# Garante que a pasta exista e aplica permissões restritas (700)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
try:
    os.chmod(UPLOAD_FOLDER, 0o700)
except Exception:
    # Se o sistema de arquivos não suportar chmod, não falha o app; apenas tenta aplicar permissões.
    pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = SECRET_KEY

# Store em memória para tokens: token -> {username, exp}
# Em produção, use Redis ou DB com TTL e suporte a revogação.
token_store = {}

# ---------------------------
# Helpers para DB simples
# ---------------------------
def read_db():
    """Lê o arquivo JSON com usuários. Se não existir, retorna estrutura padrão."""
    if not DATA_FILE.exists():
        return {"users": []}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def write_db(data):
    """Escreve dados no arquivo JSON (simples, legível)."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def find_user(username):
    """Procura um usuário existente pelo username."""
    db = read_db()
    for u in db.get("users", []):
        if u.get("username") == username:
            return u
    return None


def save_user(user_obj):
    """Salva ou atualiza um usuário na DB JSON."""
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

# ---------------------------
# Helpers de autenticação
# ---------------------------
def generate_token(username):
    """
    Gera um token seguro e registra com expiração.
    Aqui usamos um token aleatório via secrets.token_urlsafe.
    """
    token = secrets.token_urlsafe(32)
    exp = int(time.time()) + TOKEN_EXP_SECONDS
    token_store[token] = {"username": username, "exp": exp}
    return token, exp


def verify_token(token):
    """Verifica se token existe e não expirou; retorna o username ou None."""
    entry = token_store.get(token)
    if not entry:
        return None
    if entry["exp"] < int(time.time()):
        # Token expirado: remover do store
        token_store.pop(token, None)
        return None
    return entry["username"]


def require_auth(require_admin=False):
    """
    Decorator para rotas que exigem autenticação via header Authorization: Bearer <token>.
    Se require_admin=True, também checa a flag is_admin do usuário.
    """
    def decorator(f):
        @wraps(f)
        def inner(*args, **kwargs):
            # Pega o header Authorization
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
            # Anexa o usuário atual no objeto request para uso na rota
            request.current_user = user
            return f(*args, **kwargs)
        return inner
    return decorator

# ---------------------------
# Utilitários para upload/validação
# ---------------------------
def allowed_file_extension(filename):
    """Verifica se a extensão do arquivo está na whitelist."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def safe_mime_check(filename, file_stream):
    """
    Verificação simples de MIME baseado em extensão/guess.
    NOTA: não é 100% confiável. Em produção use libmagic/python-magic para checar conteúdo real.
    """
    ext = Path(filename).suffix.lower()
    guessed, _ = mimetypes.guess_type(filename)
    header_ct = request.headers.get("Content-Type")
    # Aqui apenas aceitamos se a extensão estiver na whitelist.
    return ext in ALLOWED_EXTENSIONS

# ---------------------------
# Rotas públicas / seguras
# ---------------------------
@app.route("/health", methods=["GET"])
def health():
    """Healthcheck simples — útil para monitors/CI."""
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200


@app.route("/register", methods=["POST"])
def register():
    """
    Registro de usuário (demo).
    Recebe JSON: { "username": "...", "password": "..." }.
    Observações de segurança:
      - Senha é armazenada com hash (PBKDF2 via werkzeug).
      - Não retornamos o hash em nenhuma resposta.
      - Em produção, valide força da senha, e-mail, captcha, etc.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "missing username or password"}), 400

    if find_user(username):
        return jsonify({"error": "username already exists"}), 409

    # Gera hash seguro da senha (PBKDF2-SHA256). Para produção, considere Argon2.
    pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

    # Para fins de demo local, permite criar admin se ?make_admin=1 e username == 'admin'
    is_admin = bool(request.args.get("make_admin") == "1" and username == "admin")

    user_obj = {
        "username": username,
        "password_hash": pw_hash,
        "created_at": datetime.utcnow().isoformat(),
        "is_admin": is_admin
    }
    save_user(user_obj)

    # Não retornamos senhas ou hashes
    return jsonify({"message": "user created", "username": username, "is_admin": is_admin}), 201


@app.route("/login", methods=["POST"])
def login():
    """
    Autenticação:
      - Recebe JSON com username e password.
      - Verifica hash e, se ok, gera um token Bearer.
    Observações:
      - Para produção, envie o token via cookie 'HttpOnly; Secure' ou use OAuth/OIDC.
      - Sempre operar sobre TLS em produção.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "missing username or password"}), 400

    user = find_user(username)
    if not user:
        return jsonify({"error": "invalid credentials"}), 401

    # Verifica a senha usando o hash armazenado
    if not check_password_hash(user.get("password_hash", ""), password):
        return jsonify({"error": "invalid credentials"}), 401

    # Gera token aleatório com expiração e devolve para o cliente
    token, exp = generate_token(username)
    return jsonify({
        "message": "login ok",
        "token_type": "Bearer",
        "token": token,
        "expires_at": datetime.utcfromtimestamp(exp).isoformat()
    }), 200


@app.route("/profile", methods=["GET"])
@require_auth(require_admin=False)
def profile():
    """
    Retorna apenas dados públicos do usuário autenticado (não retorna senha/hash).
    Uso: enviar header Authorization: Bearer <token>
    """
    user = request.current_user
    safe = {
        "username": user.get("username"),
        "created_at": user.get("created_at"),
        "is_admin": user.get("is_admin", False)
    }
    return jsonify({"profile": safe}), 200


@app.route("/echo", methods=["POST"])
@require_auth(require_admin=False)
def echo():
    """
    Endpoint que ecoa texto, porém:
      - limita tamanho da entrada (1 KB)
      - faz escape simples de <> para evitar XSS reflexivo se o conteúdo for mostrado em pages.
      - em aplicações reais, não reflita conteúdo do usuário em HTML sem escaping robusto.
    """
    data = request.get_data(as_text=True)[:1024]  # limitando tamanho
    # escape mínimo: substitui sinais de menor/maior
    safe = data.replace("<", "&lt;").replace(">", "&gt;")
    return current_app.response_class(f"Você enviou: {safe}", mimetype="text/plain")


@app.route("/upload", methods=["POST"])
@require_auth(require_admin=False)
def upload():
    """
    Upload seguro (versão demo):
      - valida presença do campo 'file'
      - valida extensão contra whitelist
      - renomeia para UUID para evitar colisões e path traversal
      - salva com permissões restritas (600)
      - retorna apenas o nome gerado (não o path absoluto)
    """
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    f = request.files["file"]
    if not f or f.filename == "":
        return jsonify({"error": "no file selected"}), 400

    filename = secure_filename(f.filename)
    if not allowed_file_extension(filename):
        return jsonify({"error": "file type not allowed"}), 415

    # Validação básica de mime (não substitui análise de conteúdo)
    if not safe_mime_check(filename, f.stream):
        return jsonify({"error": "mimetype mismatch or not allowed"}), 415

    # Gera nome seguro e salva fora do webroot
    ext = Path(filename).suffix.lower()
    safe_name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOAD_FOLDER / safe_name

    f.save(dest)
    try:
        os.chmod(dest, 0o600)  # rw somente para o dono
    except Exception:
        pass

    # Retorna somente o nome do arquivo salvo (não caminho completo)
    return jsonify({"message": "uploaded", "path": str(dest.name)}), 201


@app.route("/uploads/<filename>", methods=["GET"])
@require_auth(require_admin=False)
def get_uploaded_file(filename):
    """
    Serve arquivo enviado apenas para usuários autenticados.
    A rota exige o nome seguro (UUID.ext) retornado no upload.
    """
    safe_name = secure_filename(filename)
    return send_from_directory(str(UPLOAD_FOLDER), safe_name, as_attachment=True)


@app.route("/admin/log", methods=["GET"])
@require_auth(require_admin=True)
def admin_log():
    """
    Endpoint restrito a administradores para obter uma visão resumida dos usuários.
    Importante: nunca retornar hashes ou campos sensíveis.
    """
    db = read_db()
    masked = {"users": []}
    for u in db.get("users", []):
        masked["users"].append({
            "username": u.get("username"),
            "created_at": u.get("created_at"),
            "is_admin": u.get("is_admin", False)
        })
    return jsonify(masked), 200

# ---------------------------
# Execução local (apenas para laboratório)
# ---------------------------
if __name__ == "__main__":
    # Mantenha debug=False para não vazar informações sensíveis em tracebacks.
    # Em produção, execute o Flask atrás de um servidor WSGI (gunicorn/uWSGI) e um reverse proxy que faça TLS (nginx/traefik).
    app.run(host="127.0.0.1", port=5000, debug=False)

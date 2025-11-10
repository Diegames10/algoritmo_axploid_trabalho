# ============================================================
# Exploit Python / Segurança de Sistemas - ISULPAR (Laboratório)
# Servidor Flask didático com vulnerabilidades intencionais
# ============================================================

from flask import Flask, request, jsonify, send_from_directory
import json
import os
from datetime import datetime

app = Flask(__name__)

DATA_FILE = 'db_plain.json'
UPLOAD_FOLDER = 'uploads'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -----------------------------
# Funções auxiliares simples
# -----------------------------
def read_db():
    if not os.path.exists(DATA_FILE):
        return {"users": []}
    with open(DATA_FILE, 'r') as f:
        return json.load(f)


def write_db(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


# -----------------------------
# Endpoint: Healthcheck
# -----------------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "time": str(datetime.utcnow())
    })


# -----------------------------
# Endpoint: Login (INSEGURO)
# -----------------------------
@app.route('/login', methods=['POST'])
def login():
    payload = request.json or {}
    username = payload.get('username')
    password = payload.get('password')

    if not username or not password:
        return jsonify({"error": "missing fields"}), 400

    db = read_db()
    db['users'].append({
        "username": username,
        "password": password,  # ❌ Inseguro: senha armazenada em texto plano
        "created_at": str(datetime.utcnow())
    })
    write_db(db)

    # ❌ Token previsível e exposto
    token = f"token-{username}-{int(datetime.utcnow().timestamp())}"

    return jsonify({
        "message": "login ok",
        "token": token,
        "note": "use /profile?token=... for demo"
    }), 201


# -----------------------------
# Endpoint: Profile (INSEGURO)
# -----------------------------
@app.route('/profile', methods=['GET'])
def profile():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "missing token (use ?token=...)" }), 401

    # ❌ Nenhuma validação real de token
    db = read_db()
    return jsonify({
        "token_received": token,
        "users": db.get('users', [])
    })


# -----------------------------
# Endpoint: Echo (INSEGURO)
# -----------------------------
@app.route('/echo', methods=['POST'])
def echo():
    data = request.get_data(as_text=True)
    # ❌ Reflete entrada sem sanitização (XSS reflexivo)
    return app.response_class(
        f"Você enviou: {data}",
        mimetype='text/plain'
    )


# -----------------------------
# Endpoint: Upload (INSEGURO)
# -----------------------------
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "no file"}), 400

    f = request.files['file']

    # ❌ Usa nome original (sem sanitização)
    filepath = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(filepath)

    return jsonify({
        "message": "uploaded",
        "path": filepath
    }), 201


# -----------------------------
# Endpoint: Admin Log (INSEGURO)
# -----------------------------
@app.route('/admin/log', methods=['GET'])
def admin_log():
    # ❌ Exposição direta de dados sensíveis
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as fh:
            return app.response_class(fh.read(), mimetype='application/json')
    return jsonify({"error": "no db"}), 404


# -----------------------------
# Execução local
# -----------------------------
if __name__ == "__main__":
    # ⚠️ Somente em ambiente de laboratório!
    app.run(host='127.0.0.1', port=5000, debug=False)

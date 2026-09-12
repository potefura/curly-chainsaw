import io
import os
import re
import json
import base64
import hashlib
import functools
import threading
import time
from html import escape
from datetime import datetime, timedelta
from collections import defaultdict

import requests
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, make_response
from flask_cors import CORS
from PIL import Image
import torch
from facenet_pytorch import MTCNN

app = Flask(__name__)
app.secret_key = os.urandom(32)

CORS(app, resources={r"/*": {
    "origins": "*",
    "allow_headers": ["Content-Type", "X-Session-Ip"]
}})

# ── 設定 ──────────────────────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1545766347651154001/51rC_Bfsxiz1erCkVznPoHh6MTz8joM0ou6NdhrpU1UnqCNUYl6ss8fiIIL0fFTmuzUc"
SAVE_DIR     = "facedata"
DATA_DIR     = "data"
IPBANS_FILE  = os.path.join(DATA_DIR, "ipbans.json")
TRAFFIC_FILE = os.path.join(DATA_DIR, "traffic.json")
USERS_FILE   = os.path.join(DATA_DIR, "users.json")
ACCESS_LOG_FILE = os.path.join(DATA_DIR, "access_logs.json")
AGE_GUARD_FILE = os.path.join(DATA_DIR, "age_guard.json")
CONFIG_FILE = "configs.json"
IPINFO_TOKEN = ""

os.makedirs(SAVE_DIR, exist_ok=True)
os.makedirs(DATA_DIR,  exist_ok=True)

DEFAULT_CONFIG = {
    "edenai_api_key": "",
    "edenai_provider": "amazon",
    "age_detection_enabled": False,
    "api_rate_limit_enabled": False,
    "api_rate_limit_count": 10,
    "api_rate_limit_unit": "second",
}
_file_lock = threading.RLock()
_age_api_lock = threading.Lock()  # Eden AI calls are deliberately smoothed into a queue.
_rate_timestamps = []

# ── Cookie 設定 ───────────────────────────────────────────────────────────────
AUTH_COOKIE   = "ag_auth"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7   # 7日

def _make_token(username: str, pw_hash: str) -> str:
    """username + pw_hash を組み合わせた Cookie トークン生成"""
    raw = f"{username}:{pw_hash}:faceguard"
    return hashlib.sha256(raw.encode()).hexdigest()

# ── ML モデル ─────────────────────────────────────────────────────────────────
device   = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
detector = MTCNN(keep_all=True, device=device, thresholds=[0.6, 0.7, 0.7])


# ══════════════════════════════════════════════════════════════════════════════
#  JSON ユーティリティ
# ══════════════════════════════════════════════════════════════════════════════
def _load(path: str, default):
    with _file_lock:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return default

def _save(path: str, data):
    with _file_lock:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

def load_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    stored = _load(CONFIG_FILE, {})
    if isinstance(stored, dict):
        config.update(stored)
    return config

def save_config(config: dict):
    _save(CONFIG_FILE, {**DEFAULT_CONFIG, **config})


# ══════════════════════════════════════════════════════════════════════════════
#  ユーザー管理
# ══════════════════════════════════════════════════════════════════════════════
ROLE_ADMIN  = "管理者"
ROLE_VIEWER = "閲覧者"
ROLES = [ROLE_ADMIN, ROLE_VIEWER]

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def load_users() -> dict:
    users = _load(USERS_FILE, {})
    # system アカウントが存在しない場合は自動生成
    if "system" not in users:
        users["system"] = {
            "pw_hash": _hash_pw("pootefr247"),
            "role":    ROLE_ADMIN,
            "created": "system",
        }
        _save(USERS_FILE, users)
    return users

def save_users(users: dict):
    _save(USERS_FILE, users)

def get_user_by_token(token: str):
    """Cookie トークンからユーザー情報を返す。なければ None"""
    users = load_users()
    for uname, info in users.items():
        expected = _make_token(uname, info["pw_hash"])
        if token == expected:
            return uname, info
    return None, None

def current_user():
    """リクエスト中の認証済みユーザー (username, info) を返す。未認証は (None, None)"""
    token = request.cookies.get(AUTH_COOKIE, "")
    if not token:
        return None, None
    return get_user_by_token(token)

def is_admin() -> bool:
    _, info = current_user()
    return info is not None and info.get("role") == ROLE_ADMIN


# ── IP Ban ────────────────────────────────────────────────────────────────────
def load_bans() -> dict:
    return _load(IPBANS_FILE, {})

def save_bans(bans: dict):
    _save(IPBANS_FILE, bans)

def is_banned(ip: str) -> bool:
    return ip in load_bans()


# ── Traffic ───────────────────────────────────────────────────────────────────
def load_traffic() -> list:
    return _load(TRAFFIC_FILE, [])

def save_traffic(traffic: list):
    _save(TRAFFIC_FILE, traffic)

def record_traffic(ipv4, ipv6, ua, face_count, filename, ages=None):
    with _file_lock:
        traffic = load_traffic()
        traffic.append({
            "ts":         datetime.now().isoformat(timespec="seconds"),
            "ipv4":       ipv4,
            "ipv6":       ipv6,
            "ua":         ua,
            "face_count": face_count,
            "filename":   filename,
            "ages":       ages or [],
        })
        save_traffic(traffic[-5000:])

def load_access_logs() -> list:
    return _load(ACCESS_LOG_FILE, [])

def record_access_log(status: int):
    """Store a compact request log for the admin live-terminal."""
    ipv4, ipv6 = extract_ip_info(request)
    with _file_lock:
        logs = load_access_logs()
        logs.append({
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "method": request.method,
            "route": request.url_rule.rule if request.url_rule else "unmatched",
            "path": request.full_path.rstrip("?"),
            "ip": ipv4 if ipv4 != "不明" else ipv6,
            "status": status,
        })
        _save(ACCESS_LOG_FILE, logs[-5000:])

@app.after_request
def capture_access(response):
    # Polling the terminal itself would otherwise drown out useful application logs.
    if request.path != "/admin/api/access-logs":
        try:
            record_access_log(response.status_code)
        except Exception:
            app.logger.exception("access log write failed")
    return response

def _age_request_allowed(ip: str):
    """Allow three age checks per 30 seconds, then cool this IP down for one hour."""
    now = time.time()
    with _file_lock:
        guard = _load(AGE_GUARD_FILE, {})
        item = guard.get(ip, {})
        blocked_until = float(item.get("blocked_until", 0))
        if blocked_until > now:
            return False, max(1, int(blocked_until - now))
        recent = [float(t) for t in item.get("requests", []) if now - float(t) < 30]
        if len(recent) >= 3:
            guard[ip] = {"requests": [], "blocked_until": now + 3600}
            _save(AGE_GUARD_FILE, guard)
            return False, 3600
        recent.append(now)
        guard[ip] = {"requests": recent, "blocked_until": 0}
        _save(AGE_GUARD_FILE, guard)
        return True, 0

def _rate_window_seconds(unit: str) -> int:
    return {"second": 1, "hour": 3600, "day": 86400, "year": 31536000}.get(unit, 1)

def _wait_for_api_slot(config: dict):
    """Queue concurrent requests and pace them to the configured rolling-window limit."""
    if not config.get("api_rate_limit_enabled"):
        return
    limit = max(1, int(config.get("api_rate_limit_count", 1)))
    window = _rate_window_seconds(config.get("api_rate_limit_unit", "second"))
    while True:
        now = time.time()
        _rate_timestamps[:] = [stamp for stamp in _rate_timestamps if now - stamp < window]
        if len(_rate_timestamps) < limit:
            _rate_timestamps.append(now)
            return
        time.sleep(min(max(_rate_timestamps[0] + window - now, 0.01), 1.0))

def _extract_ages(payload) -> list:
    """Accept Eden AI's provider response as well as normalized face lists."""
    ages = []
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in ("age", "age_estimate", "estimated_age", "age_range"):
                    if isinstance(child, dict):
                        low = child.get("low", child.get("min"))
                        high = child.get("high", child.get("max"))
                        if "value" in child:
                            child = child["value"]
                        elif low is not None and high is not None:
                            try:
                                child = (float(low) + float(high)) / 2
                            except (TypeError, ValueError):
                                child = None
                        else:
                            child = low if low is not None else high
                    try:
                        age = int(round(float(child)))
                        if 0 <= age <= 120:
                            ages.append(age)
                    except (TypeError, ValueError):
                        pass
                else:
                    walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(payload)
    return ages

def detect_ages(image_bytes: bytes, mimetype: str, ip: str):
    config = load_config()
    if not config.get("age_detection_enabled") or not config.get("edenai_api_key"):
        return [], None
    allowed, retry_after = _age_request_allowed(ip)
    if not allowed:
        return [], retry_after
    with _age_api_lock:
        _wait_for_api_slot(config)
        response = requests.post(
            "https://api.edenai.run/v2/image/face_detection",
            headers={"Authorization": f"Bearer {config['edenai_api_key']}"},
            data={"providers": config.get("edenai_provider", "amazon")},
            files={"file": ("face.jpg", image_bytes, mimetype or "image/jpeg")},
            timeout=30,
        )
    response.raise_for_status()
    return _extract_ages(response.json()), None


# ══════════════════════════════════════════════════════════════════════════════
#  IP ユーティリティ
# ══════════════════════════════════════════════════════════════════════════════
def extract_ip_info(req):
    """
    X-Session-Ip ヘッダーおよび Cloudflare 経由のリクエストから
    端末の実 IP (IPv4 / IPv6) を安全かつ正確に抽出する関数
    """
    ipv4_list = []
    ipv6_list = []

    ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    ipv6_pattern = re.compile(r'^[0-9a-fA-F:]+$')

    raw_ip_sources = []

    # 1. フロントエンド (HTML) から明示的に送られてきた X-Session-Ip を最優先にする
    session_ip = req.headers.get("X-Session-Ip")
    if session_ip and session_ip != "なし" and session_ip != "不明":
        raw_ip_sources.append(session_ip)

    # 2. Cloudflare / プロキシヘッダーの取得
    if req.headers.get("CF-Connecting-IP"):
        raw_ip_sources.append(req.headers.get("CF-Connecting-IP"))

    if req.headers.get("X-Forwarded-For"):
        raw_ip_sources.extend(
            [ip.strip() for ip in req.headers.get("X-Forwarded-For").split(",")]
        )

    if req.remote_addr:
        raw_ip_sources.append(req.remote_addr)

    # Cloudflare 擬似 IPv4 のヘッダー値（除外用）
    pseudo_ipv4 = req.headers.get("Cf-Pseudo-IPv4")

    for ip in raw_ip_sources:
        if not ip:
            continue

        clean_ip = ip.strip("[]").split("%")[0]

        # --- IPv4 の判定 ---
        if "." in clean_ip:
            clean_ip = clean_ip.split(":")[0]
            if ipv4_pattern.match(clean_ip):
                # 127.0.0.1 や 擬似 IPv4 を弾いて本物だけを記録
                if (
                    clean_ip != "127.0.0.1"
                    and clean_ip != pseudo_ipv4
                    and clean_ip not in ipv4_list
                ):
                    ipv4_list.append(clean_ip)

        # --- IPv6 の判定 ---
        elif ":" in clean_ip:
            if ipv6_pattern.match(clean_ip):
                if clean_ip != "::1" and clean_ip not in ipv6_list:
                    ipv6_list.append(clean_ip)

    return (ipv4_list[0] if ipv4_list else "不明"), (ipv6_list[0] if ipv6_list else "不明")


def get_ipinfo(ip: str) -> dict:
    if not ip or ip in ("不明",):
        return {}
    try:
        url = f"https://ipinfo.io/{ip}/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


# ══════════════════════════════════════════════════════════════════════════════
#  Admin 認証デコレータ
# ══════════════════════════════════════════════════════════════════════════════
def admin_required(f):
    """ログイン済みなら OK（役割問わず）"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        uname, info = current_user()
        if not info:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

def admin_only(f):
    """管理者 (ROLE_ADMIN) のみ許可"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        uname, info = current_user()
        if not info:
            return redirect("/admin/login")
        if info.get("role") != ROLE_ADMIN:
            return "権限がありません (管理者のみ)", 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════════════
#  HTML テンプレート
# ══════════════════════════════════════════════════════════════════════════════
BASE_CSS = """
:root{
  --bg:#0a0c10;--bg2:#111520;--bg3:#181d2a;--bg4:#1e253a;
  --border:#252d45;--border2:#2e3a5a;
  --accent:#3b82f6;--accent2:#6366f1;--accent3:#22d3ee;
  --danger:#ef4444;--warn:#f59e0b;--ok:#10b981;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --font:'Inter',system-ui,sans-serif;
  --mono:'JetBrains Mono','Fira Code',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{color:var(--accent3)}
.shell{display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;position:fixed;top:0;left:0;height:100vh;z-index:100}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.sidebar-logo .brand{font-size:13px;font-weight:700;letter-spacing:.08em;color:var(--text);text-transform:uppercase}
.sidebar-logo .version{font-size:10px;color:var(--text3);font-family:var(--mono)}
nav{flex:1;padding:12px 0;overflow-y:auto}
nav a{display:flex;align-items:center;gap:10px;padding:9px 18px;color:var(--text2);font-size:13px;font-weight:500;border-left:2px solid transparent;transition:all .15s}
nav a:hover{color:var(--text);background:var(--bg3);border-left-color:var(--border2)}
nav a.active{color:var(--accent3);background:rgba(34,211,238,.06);border-left-color:var(--accent3)}
nav a svg{flex-shrink:0;opacity:.7}
nav a.active svg{opacity:1}
nav .nav-section{padding:16px 18px 6px;font-size:10px;letter-spacing:.12em;color:var(--text3);text-transform:uppercase;font-weight:600}
.sidebar-footer{padding:14px 18px;border-top:1px solid var(--border);font-size:11px;color:var(--text3)}
.sidebar-user{padding:12px 18px;border-top:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sidebar-avatar{width:28px;height:28px;border-radius:6px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0}
.sidebar-uname{font-size:12px;font-weight:600;color:var(--text)}
.sidebar-role{font-size:10px;color:var(--text3)}
.main{margin-left:220px;flex:1;padding:28px 32px;max-width:1400px}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
.page-title{font-size:20px;font-weight:700;color:var(--text)}
.page-sub{font-size:13px;color:var(--text3);margin-top:2px}
.topbar-right{display:flex;gap:10px;align-items:center}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.card-title{font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:18px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.stat-label{font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-val{font-size:28px;font-weight:800;color:var(--text);font-family:var(--mono);line-height:1}
.stat-sub{font-size:11px;color:var(--text3);margin-top:6px}
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
thead tr{background:var(--bg3)}
th{padding:10px 14px;font-size:11px;font-weight:600;color:var(--text3);text-align:left;letter-spacing:.06em;text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:10px 14px;font-size:13px;color:var(--text);border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:var(--mono);font-size:12px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-ok{background:rgba(16,185,129,.15);color:var(--ok)}
.badge-danger{background:rgba(239,68,68,.15);color:var(--danger)}
.badge-warn{background:rgba(245,158,11,.15);color:var(--warn)}
.badge-info{background:rgba(59,130,246,.15);color:var(--accent)}
.badge-purple{background:rgba(99,102,241,.15);color:#a5b4fc}
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;transition:all .15s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger);border:1px solid rgba(239,68,68,.3)}
.btn-danger:hover{background:var(--danger);color:#fff}
.btn-ghost{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}
.btn-ghost:hover{background:var(--bg4);color:var(--text)}
.btn-sm{padding:4px 10px;font-size:12px}
.input{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px;font-family:var(--font);width:100%}
.input:focus{outline:none;border-color:var(--accent)}
.select{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px;font-family:var(--font);width:100%;appearance:none}
.select:focus{outline:none;border-color:var(--accent)}
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px}
.alert{padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:16px;border-left:3px solid}
.alert-danger{background:rgba(239,68,68,.08);border-color:var(--danger);color:var(--danger)}
.alert-ok{background:rgba(16,185,129,.08);border-color:var(--ok);color:var(--ok)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;width:min(480px,95vw);max-height:90vh;overflow-y:auto}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.modal-close{background:none;border:none;color:var(--text3);cursor:pointer;padding:4px;border-radius:4px}
.modal-close:hover{color:var(--text);background:var(--bg3)}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg)}
.login-box{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:36px;width:360px}
.detail-row{display:flex;padding:8px 0;border-bottom:1px solid var(--border);gap:12px}
.detail-row:last-child{border-bottom:none}
.detail-key{font-size:12px;color:var(--text3);width:130px;flex-shrink:0;font-weight:500}
.detail-val{font-size:13px;color:var(--text);word-break:break-all;font-family:var(--mono)}
#toast{position:fixed;bottom:24px;right:24px;background:var(--bg4);border:1px solid var(--border);border-radius:8px;padding:12px 18px;font-size:13px;z-index:9999;opacity:0;transform:translateY(8px);transition:all .25s;pointer-events:none}
#toast.show{opacity:1;transform:translateY(0)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.gap-2{display:flex;gap:8px;flex-wrap:wrap}
.text-danger{color:var(--danger)}.text-ok{color:var(--ok)}.text-warn{color:var(--warn)}
.mt-4{margin-top:16px}.mb-4{margin-bottom:16px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.img-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.img-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;overflow:hidden;cursor:pointer;transition:all .15s}
.img-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.img-card img{width:100%;aspect-ratio:4/3;object-fit:cover;display:block}
.img-card-info{padding:8px 10px}
.img-card-ip{font-family:var(--mono);font-size:11px;color:var(--accent3)}
.img-card-ts{font-size:10px;color:var(--text3);margin-top:2px}
@media(max-width:900px){.grid-2{grid-template-columns:1fr}.sidebar{width:200px}.main{margin-left:200px;padding:16px}}
"""

TOAST_JS = """
function toast(msg,ok=true){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.style.borderColor=ok?'var(--ok)':'var(--danger)';
  t.style.color=ok?'var(--ok)':'var(--danger)';
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2800);
}
"""

def _nav(page, uname, role):
    is_adm = (role == ROLE_ADMIN)
    def li(p, label, icon):
        cls = "active" if p == page else ""
        return f'<a href="/admin/{p}" class="{cls}">{icon}{label}</a>'

    ban_link = li("bans", "IP Ban 管理",
        '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>') if is_adm else ""

    users_link = li("users", "アカウント管理",
        '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>') if is_adm else ""
    live_link = li("live-logs", "ライブアクセスログ",
        '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="18" rx="2"/><path d="m7 9 3 3-3 3m5 0h5"/></svg>') if is_adm else ""
    settings_link = li("settings", "API 設定",
        '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4"/></svg>') if is_adm else ""

    avatar = uname[0].upper()
    role_badge = f'<span class="badge {"badge-info" if is_adm else "badge-purple"}" style="font-size:9px;padding:2px 6px">{role}</span>'

    return f"""<aside class="sidebar">
  <div class="sidebar-logo">
    <svg width="32" height="32" viewBox="0 0 32 32" fill="none" style="margin-bottom:8px;display:block">
      <rect width="32" height="32" rx="8" fill="url(#lg)"/>
      <path d="M8 22l6-12 4 8 3-5 3 9" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <defs><linearGradient id="lg" x1="0" y1="0" x2="32" y2="32"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#6366f1"/></linearGradient></defs>
    </svg>
    <div class="brand">FaceGuard</div>
    <div class="version">admin panel v3</div>
  </div>
  <nav>
    <div class="nav-section">Overview</div>
    {li("dashboard","ダッシュボード",'<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>')}
    {li("traffic","トラフィック",'<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>')}
    <div class="nav-section">Security</div>
    {ban_link}
    <div class="nav-section">Data</div>
    {li("faces","顔写真ライブラリ",'<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>')}
    {li("analytics","分析レポート",'<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>')}
    {'<div class="nav-section">Admin</div>' if is_adm else ''}
    {live_link}
    {settings_link}
    {users_link}
  </nav>
  <div class="sidebar-user">
    <div class="sidebar-avatar">{avatar}</div>
    <div>
      <div class="sidebar-uname">{uname}</div>
      <div style="margin-top:2px">{role_badge}</div>
    </div>
  </div>
  <div class="sidebar-footer">
    <a href="/admin/logout" style="color:var(--text3);font-size:12px">← ログアウト</a>
  </div>
</aside>"""

def base_page(content: str, page: str, title: str) -> str:
    uname, info = current_user()
    role = info.get("role", "") if info else ""
    nav = _nav(page, uname or "?", role)
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — FaceGuard Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>{BASE_CSS}</style>
</head>
<body>
<div class="shell">
{nav}
<main class="main">
{content}
</main>
</div>
<div id="toast"></div>
<script>{TOAST_JS}</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Login / Logout
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # 既にログイン済みなら bypass
    uname, info = current_user()
    if info:
        return redirect("/admin/dashboard")

    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password", "")
        users = load_users()
        user_info = users.get(username)
        if user_info and user_info["pw_hash"] == _hash_pw(password):
            token = _make_token(username, user_info["pw_hash"])
            resp = make_response(redirect("/admin/dashboard"))
            resp.set_cookie(
                AUTH_COOKIE, token,
                httponly=True, samesite="Lax",
                max_age=COOKIE_MAX_AGE
            )
            return resp
        error = "ユーザー名またはパスワードが正しくありません"

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — FaceGuard Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>{BASE_CSS}</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-box">
    <div style="margin-bottom:28px;text-align:center">
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style="margin:0 auto 12px;display:block">
        <rect width="48" height="48" rx="12" fill="url(#lg2)"/>
        <path d="M12 34l9-18 6 12 4.5-7.5L37 34" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
        <defs><linearGradient id="lg2" x1="0" y1="0" x2="48" y2="48"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#6366f1"/></linearGradient></defs>
      </svg>
      <div style="font-size:20px;font-weight:800;color:var(--text)">FaceGuard</div>
      <div style="font-size:12px;color:var(--text3);margin-top:4px">Admin Panel</div>
    </div>
    {'<div class="alert alert-danger">' + error + '</div>' if error else ''}
    <form method="post">
      <div class="form-group">
        <label class="form-label">ユーザー名</label>
        <input type="text" name="username" class="input" placeholder="username" autofocus autocomplete="username">
      </div>
      <div class="form-group">
        <label class="form-label">パスワード</label>
        <input type="password" name="password" class="input" placeholder="••••••••••" autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;padding:10px">
        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/></svg>
        ログイン
      </button>
    </form>
  </div>
</div>
</body>
</html>"""


@app.route("/admin/logout")
def admin_logout():
    resp = make_response(redirect("/admin/login"))
    resp.delete_cookie(AUTH_COOKIE)
    return resp


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Dashboard
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    traffic = load_traffic()
    bans    = load_bans()
    users   = load_users()
    faces   = [f for f in os.listdir(SAVE_DIR) if f.endswith(".jpg")]
    total   = len(traffic)
    ban_c   = len(bans)
    now     = datetime.now()
    last24  = [t for t in traffic if (now - datetime.fromisoformat(t["ts"])).total_seconds() < 86400]
    face24  = sum(1 for t in last24 if t.get("face_count", 0) > 0)

    day_counts = defaultdict(int)
    for t in traffic:
        day_counts[t["ts"][:10]] += 1
    days_sorted = sorted(day_counts.keys())[-7:]
    bar_labels  = json.dumps(days_sorted)
    bar_data    = json.dumps([day_counts[d] for d in days_sorted])

    ip_counts = defaultdict(int)
    for t in traffic:
        ip_counts[t.get("ipv4","不明")] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    can_ban = is_admin()
    top_ip_rows = ""
    for ip, cnt in top_ips:
        ban_badge = '<span class="badge badge-danger">BAN</span>' if ip in bans else ""
        ban_btn = ""
        if can_ban:
            ban_btn = f'<form style="display:inline" method="post" action="/admin/bans/add"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-danger btn-sm" type="submit">BAN</button></form>' if ip not in bans else '<span class="badge badge-danger">Banned</span>'
        top_ip_rows += f"""<tr>
          <td class="mono">{ip}</td>
          <td class="mono">{cnt}</td>
          <td>{ban_badge}</td>
          <td><div class="gap-2"><a href="/admin/traffic?ip={ip}" class="btn btn-ghost btn-sm"> 詳細</a>{ban_btn}</div></td>
        </tr>"""

    # アカウント一覧 (管理者のみ表示)
    users_section = ""
    if can_ban:
        user_rows = ""
        for uname, uinfo in users.items():
            role = uinfo.get("role", "")
            rb = f'<span class="badge {"badge-info" if role==ROLE_ADMIN else "badge-purple"}">{role}</span>'
            created = uinfo.get("created","")
            sys_badge = '<span class="badge badge-warn">system</span>' if uname == "system" else ""
            del_btn = "" if uname == "system" else f'<form style="display:inline" method="post" action="/admin/users/delete"><input type="hidden" name="username" value="{uname}"><button class="btn btn-danger btn-sm" type="submit" onclick="return confirm(\'削除しますか?\')">削除</button></form>'
            user_rows += f"""<tr>
              <td class="mono">{uname} {sys_badge}</td>
              <td>{rb}</td>
              <td style="color:var(--text3);font-size:12px">{created}</td>
              <td>{del_btn}</td>
            </tr>"""
        users_section = f"""
<div class="card mb-4">
  <div class="card-header">
    <div class="card-title">
      <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
      アカウント一覧
    </div>
    <button class="btn btn-primary btn-sm" onclick="document.getElementById('modal-user').classList.add('open')">
      + 新規作成
    </button>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>ユーザー名</th><th>役割</th><th>作成日時</th><th></th></tr></thead>
      <tbody>{user_rows}</tbody>
    </table>
  </div>
</div>

<!-- 新規ユーザー作成モーダル -->
<div class="modal-overlay" id="modal-user" onclick="if(event.target===this)this.classList.remove('open')">
  <div class="modal">
    <div class="modal-header">
      <div style="font-size:15px;font-weight:700">新規アカウント作成</div>
      <button class="modal-close" onclick="document.getElementById('modal-user').classList.remove('open')">
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <form method="post" action="/admin/users/create">
      <div class="form-group">
        <label class="form-label">ユーザー名</label>
        <input class="input" name="username" placeholder="username" required>
      </div>
      <div class="form-group">
        <label class="form-label">パスワード</label>
        <input class="input" type="password" name="password" placeholder="••••••••••" required>
      </div>
      <div class="form-group">
        <label class="form-label">役割</label>
        <select class="select" name="role">
          <option value="{ROLE_ADMIN}">{ROLE_ADMIN} — BAN操作・全機能</option>
          <option value="{ROLE_VIEWER}">{ROLE_VIEWER} — 閲覧のみ</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">
        作成する
      </button>
    </form>
  </div>
</div>"""

    content = f"""
<div class="topbar">
  <div>
    <div class="page-title">ダッシュボード</div>
    <div class="page-sub">システム概要と直近の活動</div>
  </div>
  <div class="topbar-right">
    <span class="badge badge-ok">● 稼働中</span>
    <span style="font-size:11px;color:var(--text3)">{now.strftime('%Y-%m-%d %H:%M')}</span>
  </div>
</div>

<div class="stat-grid">
  <div class="stat">
    <div class="stat-label">総リクエスト</div>
    <div class="stat-val">{total:,}</div>
    <div class="stat-sub">全期間</div>
  </div>
  <div class="stat">
    <div class="stat-label">顔検出 (24h)</div>
    <div class="stat-val">{face24}</div>
    <div class="stat-sub">直近24時間</div>
  </div>
  <div class="stat">
    <div class="stat-label">保存済み顔画像</div>
    <div class="stat-val">{len(faces)}</div>
    <div class="stat-sub">facedata/</div>
  </div>
  <div class="stat">
    <div class="stat-label">Ban 中 IP</div>
    <div class="stat-val" style="color:var(--danger)">{ban_c}</div>
    <div class="stat-sub">アクティブ Ban</div>
  </div>
</div>

<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-title">直近7日間のリクエスト数</div></div>
    <div class="chart-container">
      <canvas id="barChart"></canvas>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-title">Top 5 送信元 IP</div></div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>IP</th><th>回数</th><th>Ban</th><th></th></tr></thead>
        <tbody>{top_ip_rows if top_ip_rows else '<tr><td colspan="4" style="color:var(--text3);text-align:center;padding:24px">データなし</td></tr>'}</tbody>
      </table>
    </div>
  </div>
</div>

{users_section}

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
new Chart(document.getElementById('barChart').getContext('2d'),{{
  type:'bar',
  data:{{labels:{bar_labels},datasets:[{{label:'リクエスト',data:{bar_data},backgroundColor:'rgba(59,130,246,0.6)',borderColor:'#3b82f6',borderWidth:1,borderRadius:4}}]}},
  options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'rgba(255,255,255,.04)'}},ticks:{{color:'#64748b',font:{{size:11}}}}}},
             y:{{grid:{{color:'rgba(255,255,255,.04)'}},ticks:{{color:'#64748b',font:{{size:11}}}}}}}}}}
}});
</script>
"""
    return base_page(content, "dashboard", "ダッシュボード")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: ユーザー管理 (専用ページ)
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/users")
@admin_only
def admin_users():
    users = load_users()
    msg   = request.args.get("msg","")
    err   = request.args.get("err","")

    rows = ""
    for uname, uinfo in users.items():
        role = uinfo.get("role","")
        rb = f'<span class="badge {"badge-info" if role==ROLE_ADMIN else "badge-purple"}">{role}</span>'
        created = uinfo.get("created","")
        sys_badge = '<span class="badge badge-warn" style="font-size:9px">system</span>' if uname=="system" else ""
        del_btn = "" if uname=="system" else f"""
          <form style="display:inline" method="post" action="/admin/users/delete">
            <input type="hidden" name="username" value="{uname}">
            <button class="btn btn-danger btn-sm" type="submit" onclick="return confirm('「{uname}」を削除しますか?')">削除</button>
          </form>"""
        rows += f"""<tr>
          <td class="mono">{uname} {sys_badge}</td>
          <td>{rb}</td>
          <td style="color:var(--text3);font-size:12px">{created}</td>
          <td>{del_btn}</td>
        </tr>"""

    alert = ""
    if msg:
        alert = f'<div class="alert alert-ok">{msg}</div>'
    elif err:
        alert = f'<div class="alert alert-danger">{err}</div>'

    content = f"""
<div class="topbar">
  <div>
    <div class="page-title">アカウント管理</div>
    <div class="page-sub">現在 {len(users)} アカウント</div>
  </div>
</div>
{alert}
<div class="grid-2">
  <div class="card">
    <div class="card-header"><div class="card-title">新規アカウント作成</div></div>
    <form method="post" action="/admin/users/create">
      <div class="form-group">
        <label class="form-label">ユーザー名</label>
        <input class="input" name="username" placeholder="username" required>
      </div>
      <div class="form-group">
        <label class="form-label">パスワード</label>
        <input class="input" type="password" name="password" placeholder="••••••••••" required>
      </div>
      <div class="form-group">
        <label class="form-label">役割</label>
        <select class="select" name="role">
          <option value="{ROLE_ADMIN}">{ROLE_ADMIN} — BAN操作・全機能</option>
          <option value="{ROLE_VIEWER}">{ROLE_VIEWER} — 閲覧のみ</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
        作成する
      </button>
    </form>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-title">アカウント一覧</div></div>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>ユーザー名</th><th>役割</th><th>作成日時</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>
"""
    return base_page(content, "users", "アカウント管理")


@app.route("/admin/users/create", methods=["POST"])
@admin_only
def admin_users_create():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", ROLE_VIEWER)
    if role not in ROLES:
        role = ROLE_VIEWER

    if not username or not password:
        return redirect("/admin/users?err=ユーザー名とパスワードは必須です")

    users = load_users()
    if username in users:
        return redirect(f"/admin/users?err=「{username}」は既に存在します")

    users[username] = {
        "pw_hash": _hash_pw(password),
        "role":    role,
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    save_users(users)
    ref = request.referrer or ""
    if "dashboard" in ref:
        return redirect("/admin/dashboard")
    return redirect(f"/admin/users?msg=「{username}」を作成しました")


@app.route("/admin/users/delete", methods=["POST"])
@admin_only
def admin_users_delete():
    username = (request.form.get("username") or "").strip()
    if username == "system":
        return redirect("/admin/users?err=system アカウントは削除できません")
    users = load_users()
    users.pop(username, None)
    save_users(users)
    ref = request.referrer or ""
    if "dashboard" in ref:
        return redirect("/admin/dashboard")
    return redirect(f"/admin/users?msg=「{username}」を削除しました")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Traffic
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/traffic")
@admin_required
def admin_traffic():
    traffic   = load_traffic()
    bans      = load_bans()
    filter_ip = request.args.get("ip","").strip()
    can_ban   = is_admin()

    if filter_ip:
        traffic = [t for t in traffic if t.get("ipv4")==filter_ip or t.get("ipv6")==filter_ip]

    rows = ""
    for t in list(reversed(traffic))[:200]:
        ip    = t.get("ipv4","不明")
        ipv6  = t.get("ipv6","不明")
        ua    = t.get("ua","不明") or "不明"
        fc    = t.get("face_count",0)
        fname = t.get("filename") or ""
        ts    = t.get("ts","")
        banned_badge = '<span class="badge badge-danger">BAN</span>' if ip in bans else ""
        face_badge   = f'<span class="badge badge-ok">{fc}人</span>' if fc>0 else '<span class="badge" style="background:rgba(255,255,255,.05);color:var(--text3)">0</span>'
        img_link     = f'<a href="/admin/faces?ip={ip}" class="btn btn-ghost btn-sm">写真</a>' if fname else ""
        ban_btn      = ""
        if can_ban and ip not in bans:
            ban_btn = f'<form style="display:inline" method="post" action="/admin/bans/add"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-danger btn-sm" type="submit">BAN</button></form>'
        ua_short = (ua[:40]+"…") if len(ua)>40 else ua
        rows += f"""<tr>
          <td style="color:var(--text3);font-size:11px">{ts}</td>
          <td class="mono">{ip} {banned_badge}</td>
          <td class="mono" style="color:var(--text3)">{ipv6[:24]+'…' if len(ipv6)>24 else ipv6}</td>
          <td>{face_badge}</td>
          <td style="color:var(--text3);font-size:12px" title="{ua}">{ua_short}</td>
          <td><div class="gap-2"><a href="/admin/ip/{ip}" class="btn btn-ghost btn-sm">詳細</a>{img_link}{ban_btn}</div></td>
        </tr>"""

    filter_note = f'<div class="alert alert-ok" style="margin-bottom:12px">IP フィルター: <span class="mono">{filter_ip}</span> &nbsp;<a href="/admin/traffic" class="btn btn-ghost btn-sm">解除</a></div>' if filter_ip else ""

    content = f"""
<div class="topbar">
  <div><div class="page-title">トラフィックログ</div><div class="page-sub">直近 200 件</div></div>
  <div class="topbar-right">
    <form method="get" style="display:flex;gap:8px">
      <input class="input" name="ip" placeholder="IP でフィルター" value="{filter_ip}" style="width:180px">
      <button class="btn btn-primary" type="submit">検索</button>
    </form>
  </div>
</div>
{filter_note}
<div class="card">
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>日時</th><th>IPv4</th><th>IPv6</th><th>顔</th><th>User-Agent</th><th>操作</th></tr></thead>
      <tbody>{rows if rows else '<tr><td colspan="6" style="color:var(--text3);text-align:center;padding:32px">データなし</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
    return base_page(content, "traffic", "トラフィック")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: IP Detail
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/ip/<ip>")
@admin_required
def admin_ip_detail(ip):
    info      = get_ipinfo(ip)
    traffic   = load_traffic()
    bans      = load_bans()
    can_ban   = is_admin()
    ip_logs   = [t for t in traffic if t.get("ipv4")==ip or t.get("ipv6")==ip]
    face_logs = [t for t in ip_logs if t.get("face_count",0)>0]
    is_ban    = ip in bans

    def row(k,v):
        return f'<div class="detail-row"><div class="detail-key">{k}</div><div class="detail-val">{v or "不明"}</div></div>'

    info_html = (
        row("国", f"{info.get('country','不明')} — {info.get('city','不明')}, {info.get('region','')}")
        + row("組織 / ASN", info.get("org","不明"))
        + row("ホスト名", info.get("hostname","不明"))
        + row("タイムゾーン", info.get("timezone","不明"))
        + row("座標", info.get("loc","不明"))
        + row("アクセス回数", str(len(ip_logs)))
        + row("顔検出回数", str(len(face_logs)))
        + row("最終アクセス", ip_logs[-1]["ts"] if ip_logs else "不明")
        + row("Ban 状態", "🚫 BAN 中" if is_ban else "✅ 正常")
    )

    img_html = ""
    for t in reversed(face_logs):
        fname = t.get("filename")
        if fname:
            fpath = os.path.join(SAVE_DIR, fname)
            if os.path.exists(fpath):
                with open(fpath,"rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                img_html += f"""<div class="img-card">
                  <img src="data:image/jpeg;base64,{b64}" loading="lazy">
                  <div class="img-card-info">
                    <div class="img-card-ts">{t['ts']}</div>
                    <div class="img-card-ts" style="color:var(--ok)">{t['face_count']}人検出</div>
                  </div>
                </div>"""

    ban_btn = ""
    if can_ban:
        if is_ban:
            ban_btn = f'<form method="post" action="/admin/bans/remove" style="display:inline"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-ghost">🔓 Ban 解除</button></form>'
        else:
            ban_btn = f'<form method="post" action="/admin/bans/add" style="display:inline"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-danger">🚫 このIPをBan</button></form>'

    content = f"""
<div class="topbar">
  <div><div class="page-title">IP 詳細: <span style="font-family:var(--mono);color:var(--accent3)">{ip}</span></div></div>
  <div class="topbar-right">{ban_btn}<a href="/admin/traffic?ip={ip}" class="btn btn-ghost">ログ表示</a></div>
</div>
<div class="grid-2 mb-4">
  <div class="card"><div class="card-header"><div class="card-title">IP 情報</div></div>{info_html}</div>
  <div class="card">
    <div class="card-header"><div class="card-title">ステータス</div></div>
    <div style="text-align:center;padding:24px">
      <div style="font-size:48px;margin-bottom:12px">{'🚫' if is_ban else '✅'}</div>
      <div style="font-size:16px;font-weight:700;color:{'var(--danger)' if is_ban else 'var(--ok)'}">{'BAN 中' if is_ban else '正常'}</div>
      <div style="margin-top:16px">{ban_btn}</div>
    </div>
  </div>
</div>
{'<div class="card"><div class="card-header"><div class="card-title">このIPの顔写真 (' + str(len(face_logs)) + '件)</div></div><div class="img-grid">' + img_html + '</div></div>' if img_html else '<div class="card" style="padding:32px;text-align:center;color:var(--text3)">このIPの顔写真 はありません</div>'}
"""
    return base_page(content, "traffic", f"IP詳細: {ip}")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: IP Ban
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/bans")
@admin_only
def admin_bans():
    bans = load_bans()
    rows = ""
    for ip, meta in bans.items():
        ts = meta.get("banned_at","不明") if isinstance(meta,dict) else "不明"
        rows += f"""<tr>
          <td class="mono">{ip}</td>
          <td style="color:var(--text3);font-size:12px">{ts}</td>
          <td>
            <div class="gap-2">
              <a href="/admin/ip/{ip}" class="btn btn-ghost btn-sm">詳細</a>
              <form method="post" action="/admin/bans/remove" style="display:inline">
                <input type="hidden" name="ip" value="{ip}">
                <button class="btn btn-ghost btn-sm text-ok" type="submit">解除</button>
              </form>
            </div>
          </td>
        </tr>"""

    content = f"""
<div class="topbar">
  <div><div class="page-title">IP Ban 管理</div><div class="page-sub">現在 <strong>{len(bans)}</strong> 件の Ban が有効</div></div>
</div>
<div class="card mb-4">
  <div class="card-header"><div class="card-title">IP を手動 Ban</div></div>
  <form method="post" action="/admin/bans/add" style="display:flex;gap:10px;align-items:flex-end">
    <div style="flex:1"><div class="form-label">IP アドレス</div><input class="input" name="ip" placeholder="192.168.0.1" required></div>
    <button class="btn btn-danger" type="submit" style="white-space:nowrap">Ban する</button>
  </form>
</div>
<div class="card">
  <div class="card-header"><div class="card-title">Ban リスト</div></div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>IP アドレス</th><th>Ban 日時</th><th>操作</th></tr></thead>
      <tbody>{rows if rows else '<tr><td colspan="3" style="color:var(--text3);text-align:center;padding:32px">Ban されている IP はありません</td></tr>'}</tbody>
    </table>
  </div>
</div>"""
    return base_page(content, "bans", "IP Ban 管理")


@app.route("/admin/bans/add", methods=["POST"])
@admin_only
def admin_bans_add():
    ip   = (request.form.get("ip") or "").strip()
    bans = load_bans()
    if ip:
        bans[ip] = {"banned_at": datetime.now().isoformat(timespec="seconds")}
        save_bans(bans)
    return redirect(request.referrer or "/admin/bans")


@app.route("/admin/bans/remove", methods=["POST"])
@admin_only
def admin_bans_remove():
    ip   = (request.form.get("ip") or "").strip()
    bans = load_bans()
    bans.pop(ip, None)
    save_bans(bans)
    return redirect(request.referrer or "/admin/bans")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Faces
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/faces")
@admin_required
def admin_faces():
    filter_ip = request.args.get("ip","").strip()
    traffic   = load_traffic()
    can_ban   = is_admin()
    fn_map    = {t["filename"]:t for t in traffic if t.get("filename")}
    files     = sorted([f for f in os.listdir(SAVE_DIR) if f.endswith(".jpg")], reverse=True)

    if filter_ip:
        files = [f for f in files if filter_ip.replace(":","_").replace(" ","_") in f or
                 fn_map.get(f,{}).get("ipv4")==filter_ip]

    cards = ""
    for fname in files[:120]:
        fpath = os.path.join(SAVE_DIR, fname)
        meta  = fn_map.get(fname,{})
        ip    = meta.get("ipv4","不明")
        ts    = meta.get("ts","")
        fc    = meta.get("face_count",0)
        try:
            with open(fpath,"rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            img_tag = f'<img src="data:image/jpeg;base64,{b64}" loading="lazy">'
        except Exception:
            b64 = ""
            img_tag = '<div style="aspect-ratio:4/3;background:var(--bg3);display:flex;align-items:center;justify-content:center;color:var(--text3)">読込失敗</div>'
        delete_form = f'''<form method="post" action="/admin/faces/delete" onclick="event.stopPropagation()" style="margin-top:8px"><input type="hidden" name="filename" value="{escape(fname)}"><button class="btn btn-danger btn-sm" style="width:100%;justify-content:center" onclick="return confirm('この画像を削除しますか?')">画像を削除</button></form>''' if can_ban else ""
        cards += f"""<div class="img-card" onclick="openModal('{escape(fname)}','{escape(ip)}','{escape(ts)}','{fc}',`{b64}`)">
          {img_tag}
          <div class="img-card-info">
            <div class="img-card-ip">{ip}</div>
            <div class="img-card-ts">{ts}</div>
            <div class="img-card-ts" style="color:var(--ok)">{fc}人</div>
            {delete_form}
          </div>
        </div>"""

    filter_note = f'<div class="alert alert-ok" style="margin-bottom:12px">IP フィルター: <span class="mono">{filter_ip}</span> &nbsp;<a href="/admin/faces" class="btn btn-ghost btn-sm">解除</a></div>' if filter_ip else ""

    ban_modal_btn = '<button class="btn btn-danger" id="modal-ban-btn" onclick="banIp()">🚫 この IP を BAN</button>' if can_ban else ""

    content = f"""
<div class="topbar">
  <div><div class="page-title">顔写真ライブラリ</div><div class="page-sub">最大120件表示</div></div>
  <div class="topbar-right">
    <form method="get" style="display:flex;gap:8px">
      <input class="input" name="ip" placeholder="IP でフィルター" value="{filter_ip}" style="width:180px">
      <button class="btn btn-primary" type="submit">検索</button>
    </form>
  </div>
</div>
{filter_note}
<div class="card">
  {('<div class="img-grid">' + cards + '</div>') if cards else '<div style="padding:48px;text-align:center;color:var(--text3)">顔写真がありません</div>'}
</div>

<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-header">
      <div style="font-size:15px;font-weight:700">写真詳細</div>
      <button class="modal-close" onclick="closeModal()">
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <img id="modal-img" style="width:100%;border-radius:8px;margin-bottom:16px">
    <div id="modal-details"></div>
    <div class="mt-4 gap-2">
      {ban_modal_btn}
      <a id="modal-log-link" href="#" class="btn btn-ghost">ログ表示</a>
    </div>
  </div>
</div>
<script>
let _ip='';
function openModal(fname,ip,ts,fc,b64){{
  _ip=ip;
  document.getElementById('modal-img').src='data:image/jpeg;base64,'+b64;
  document.getElementById('modal-details').innerHTML=`
    <div class="detail-row"><div class="detail-key">ファイル名</div><div class="detail-val">${{fname}}</div></div>
    <div class="detail-row"><div class="detail-key">IPv4</div><div class="detail-val">${{ip}}</div></div>
    <div class="detail-row"><div class="detail-key">日時</div><div class="detail-val">${{ts}}</div></div>
    <div class="detail-row"><div class="detail-key">顔検出数</div><div class="detail-val">${{fc}}人</div></div>
  `;
  document.getElementById('modal-log-link').href='/admin/traffic?ip='+encodeURIComponent(ip);
  document.getElementById('modal').classList.add('open');
}}
function closeModal(){{document.getElementById('modal').classList.remove('open');}}
function banIp(){{
  if(!_ip)return;
  fetch('/admin/api/ban',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{ip:_ip}})}})
  .then(r=>r.json()).then(d=>{{toast(d.msg||'BANしました');closeModal();}}).catch(()=>toast('エ ラー',false));
}}
</script>"""
    return base_page(content, "faces", "顔写真ライブラリ")


@app.route("/admin/faces/delete", methods=["POST"])
@admin_only
def admin_faces_delete():
    filename = os.path.basename(request.form.get("filename", ""))
    if not filename.lower().endswith(".jpg"):
        return "不正なファイル名です", 400
    path = os.path.join(SAVE_DIR, filename)
    if os.path.isfile(path):
        os.remove(path)
    traffic = load_traffic()
    for item in traffic:
        if item.get("filename") == filename:
            item["filename"] = None
    save_traffic(traffic)
    return redirect(request.referrer or "/admin/faces")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Analytics
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    traffic = load_traffic()
    ip_counts    = defaultdict(int)
    face_by_hour = defaultdict(int)
    req_by_hour  = defaultdict(int)
    ua_counts    = defaultdict(int)
    daily        = defaultdict(int)
    age_counts   = {"0–12": 0, "13–19": 0, "20–39": 0, "40–59": 0, "60+": 0}
    for t in traffic:
        ip = t.get("ipv4","不明")
        ip_counts[ip] += 1
        ts = t.get("ts","")
        fc = t.get("face_count",0)
        ua = (t.get("ua","不明") or "不明").lower()
        if len(ts)>=13:
            h = ts[11:13]
            req_by_hour[h] += 1
            if fc>0: face_by_hour[h] += 1
        if len(ts)>=10: daily[ts[:10]] += 1
        if "mobile" in ua or "android" in ua or "iphone" in ua:
            ua_counts["モバイル"] += 1
        elif "bot" in ua or "crawl" in ua:
            ua_counts["Bot"] += 1
        else:
            ua_counts["デスクトップ"] += 1
        for age in t.get("ages", []):
            try:
                age = int(age)
                bucket = "0–12" if age <= 12 else "13–19" if age <= 19 else "20–39" if age <= 39 else "40–59" if age <= 59 else "60+"
                age_counts[bucket] += 1
            except (TypeError, ValueError):
                pass

    top_ips     = sorted(ip_counts.items(), key=lambda x:x[1], reverse=True)[:8]
    hours       = [f"{i:02d}" for i in range(24)]
    req_h_data  = json.dumps([req_by_hour.get(h,0) for h in hours])
    face_h_data = json.dumps([face_by_hour.get(h,0) for h in hours])
    days_sorted = sorted(daily.keys())[-14:]
    daily_labels= json.dumps(days_sorted)
    daily_data  = json.dumps([daily.get(d,0) for d in days_sorted])
    ua_labels   = list(ua_counts.keys())
    ua_vals     = [ua_counts[k] for k in ua_labels]
    ua_colors   = ["#3b82f6","#10b981","#f59e0b","#ef4444"]

    donut_items = ""
    total_ua = sum(ua_vals) or 1
    for i,(k,v) in enumerate(zip(ua_labels,ua_vals)):
        pct = round(v/total_ua*100)
        donut_items += f'<div style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:8px"><div style="width:10px;height:10px;border-radius:50%;background:{ua_colors[i%4]};flex-shrink:0"></div><div style="color:var(--text2);flex:1">{k}</div><div style="font-family:var(--mono);color:var(--text);font-weight:600">{pct}%</div></div>'

    bans    = load_bans()
    can_ban = is_admin()
    ip_rows = ""
    for rank,(ip,cnt) in enumerate(top_ips,1):
        pct = round(cnt/len(traffic)*100) if traffic else 0
        det_btn = f'<a href="/admin/ip/{ip}" class="btn btn-ghost btn-sm">詳細</a>'
        ip_rows += f"""<tr>
          <td style="color:var(--text3);font-family:var(--mono)">{rank}</td>
          <td class="mono">{ip} {'<span class="badge badge-danger">BAN</span>' if ip in bans else ''}</td>
          <td class="mono">{cnt}</td>
          <td><div style="height:6px;background:var(--bg4);border-radius:3px;width:120px"><div style="height:100%;width:{pct}%;background:var(--accent);border-radius:3px"></div></div></td>
          <td>{det_btn}</td>
        </tr>"""

    content = f"""
<div class="topbar">
  <div><div class="page-title">分析レポート</div><div class="page-sub">アクセスパターン・IP分布 ・時間帯分析</div></div>
</div>
<div class="grid-2 mb-4">
  <div class="card">
    <div class="card-header"><div class="card-title">時間帯別リクエスト / 顔検出</div></div>
    <div class="chart-container">
      <canvas id="hourChart"></canvas>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><div class="card-title">デバイス種別</div></div>
    <div style="display:flex;align-items:center;gap:24px;padding:16px 0">
      <canvas id="donutChart" width="140" height="140" style="flex-shrink:0"></canvas>
      <div style="flex:1">{donut_items}</div>
    </div>
  </div>
</div>
<div class="card mb-4">
  <div class="card-header"><div class="card-title">年齢層（Eden AI 推定）</div><span class="badge badge-purple">閲覧者にも表示</span></div>
  <div style="height:280px"><canvas id="ageChart"></canvas></div>
</div>
<div class="card mb-4">
  <div class="card-header"><div class="card-title">14日間トレンド</div></div>
  <div class="chart-container">
    <canvas id="lineChart"></canvas>
  </div>
</div>
<div class="card">
  <div class="card-header"><div class="card-title">IP ランキング (Top 8)</div></div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>#</th><th>IP</th><th>リクエスト数</th><th>割合</th><th></th></tr></thead>
      <tbody>{ip_rows if ip_rows else '<tr><td colspan="5" style="color:var(--text3);text-align:center;padding:24px">データなし</td></tr>'}</tbody>
    </table>
  </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
const GRID='rgba(255,255,255,.04)',TICK={{color:'#64748b',font:{{size:10}}}};
new Chart(document.getElementById('hourChart'),{{type:'bar',data:{{labels:{json.dumps(hours)},datasets:[{{label:'リクエスト',data:{req_h_data},backgroundColor:'rgba(59,130,246,.5)',borderColor:'#3b82f6',borderWidth:1,borderRadius:3}},{{label:'顔検出',data:{face_h_data},backgroundColor:'rgba(16,185,129,.5)',borderColor:'#10b981',borderWidth:1,borderRadius:3}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}}}},scales:{{x:{{grid:{{color:GRID}},ticks:TICK}},y:{{grid:{{color:GRID}},ticks:TICK}}}}}}}});
new Chart(document.getElementById('donutChart'),{{type:'doughnut',data:{{labels:{json.dumps(ua_labels)},datasets:[{{data:{json.dumps(ua_vals)},backgroundColor:{json.dumps(ua_colors[:len(ua_labels)])},borderWidth:0}}]}},options:{{responsive:false,plugins:{{legend:{{display:false}}}}}}}});
new Chart(document.getElementById('ageChart'),{{type:'doughnut',data:{{labels:{json.dumps(list(age_counts.keys()))},datasets:[{{data:{json.dumps(list(age_counts.values()))},backgroundColor:['#22d3ee','#3b82f6','#6366f1','#f59e0b','#ef4444'],borderWidth:0}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'right',labels:{{color:'#94a3b8'}}}}}}}}}});
new Chart(document.getElementById('lineChart'),{{type:'line',data:{{labels:{daily_labels},datasets:[{{label:'リクエスト',data:{daily_data},borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,.08)',borderWidth:2,fill:true,tension:.4,pointRadius:3,pointBackgroundColor:'#6366f1'}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}}}},scales:{{x:{{grid:{{color:GRID}},ticks:TICK}},y:{{grid:{{color:GRID}},ticks:TICK}}}}}}}});
</script>"""
    return base_page(content, "analytics", "分析レポート")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: Eden AI / rate limit settings
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/settings", methods=["GET", "POST"])
@admin_only
def admin_settings():
    config = load_config()
    saved = False
    if request.method == "POST":
        key = request.form.get("edenai_api_key", "").strip()
        # A blank key keeps the existing secret; the explicit button clears it.
        if key:
            config["edenai_api_key"] = key
        if request.form.get("clear_api_key") == "1":
            config["edenai_api_key"] = ""
        config["edenai_provider"] = request.form.get("edenai_provider", "amazon").strip() or "amazon"
        config["age_detection_enabled"] = request.form.get("age_detection_enabled") == "on"
        config["api_rate_limit_enabled"] = request.form.get("api_rate_limit_enabled") == "on"
        try:
            config["api_rate_limit_count"] = max(1, int(request.form.get("api_rate_limit_count", 10)))
        except ValueError:
            config["api_rate_limit_count"] = 10
        unit = request.form.get("api_rate_limit_unit", "second")
        config["api_rate_limit_unit"] = unit if unit in ("second", "hour", "day", "year") else "second"
        save_config(config)
        saved = True

    checked = lambda value: "checked" if value else ""
    options = "".join(f'<option value="{unit}" {"selected" if config["api_rate_limit_unit"] == unit else ""}>{label}</option>' for unit, label in (("second", "秒"), ("hour", "時間"), ("day", "日"), ("year", "年")))
    masked = "設定済み（末尾 " + escape(config["edenai_api_key"][-4:]) + "）" if config.get("edenai_api_key") else "未設定"
    content = f"""
<div class="topbar"><div><div class="page-title">API 設定</div><div class="page-sub">Eden AI 年齢判定と呼び出し速度を管理</div></div></div>
{'<div class="alert alert-ok">設定を configs.json に保存しました</div>' if saved else ''}
<form method="post"><div class="grid-2">
 <div class="card"><div class="card-header"><div class="card-title">Eden AI 顔年齢判定</div></div>
   <div class="form-group"><label class="form-label">API Key — {masked}</label><input class="input" type="password" name="edenai_api_key" autocomplete="new-password" placeholder="変更する場合のみ入力"></div>
   <div class="form-group"><label class="form-label">Provider</label><input class="input" name="edenai_provider" value="{escape(str(config['edenai_provider']))}"></div>
   <label class="form-label"><input type="checkbox" name="age_detection_enabled" {checked(config['age_detection_enabled'])}> 年齢判定を有効にする</label>
   <label class="form-label" style="margin-top:12px"><input type="checkbox" name="clear_api_key" value="1"> 保存済み API Key を削除</label>
 </div>
 <div class="card"><div class="card-header"><div class="card-title">API レートリミット</div><span class="badge badge-warn">初期値: 無効</span></div>
   <label class="form-label"><input type="checkbox" name="api_rate_limit_enabled" {checked(config['api_rate_limit_enabled'])}> レートリミットを有効にする</label>
   <div class="grid-2 mt-4"><div class="form-group"><label class="form-label">回数</label><input class="input" type="number" min="1" name="api_rate_limit_count" value="{config['api_rate_limit_count']}"></div><div class="form-group"><label class="form-label">期間</label><select class="select" name="api_rate_limit_unit">{options}</select></div></div>
   <p style="font-size:12px;color:var(--text3);margin-bottom:18px">同時アクセスはキューで直列化し、設定したローリング期間に合わせて Eden AI 呼び出しを調節します。同一 IP の年齢判定は30秒に3回まで、超過時は1時間停止します。</p>
   <button class="btn btn-primary" type="submit">設定を保存</button>
 </div>
</div></form>"""
    return base_page(content, "settings", "API 設定")


@app.route("/admin/live-logs")
@admin_only
def admin_live_logs():
    content = """
<div class="topbar"><div><div class="page-title">ライブアクセスログ</div><div class="page-sub">ルート・IP・パス・レスポンスコードをリアルタイム表示</div></div><form method="post" action="/admin/logs/clear"><button class="btn btn-danger" onclick="return confirm('アクセスログを全件削除しますか?')">ログをクリア</button></form></div>
<div class="card" style="padding:0;overflow:hidden;border-color:#334155">
 <div style="height:42px;background:#161b22;display:flex;align-items:center;gap:7px;padding:0 14px;border-bottom:1px solid #30363d">
  <svg width="54" height="14" viewBox="0 0 54 14" aria-label="terminal controls"><circle cx="7" cy="7" r="6" fill="#ff5f57"/><circle cx="27" cy="7" r="6" fill="#febc2e"/><circle cx="47" cy="7" r="6" fill="#28c840"/></svg>
  <span style="font:12px var(--mono);color:#8b949e;margin-left:10px">faceguard — access.log — live</span><span class="badge badge-ok" style="margin-left:auto">● LIVE</span>
 </div>
 <pre id="terminal" style="height:620px;overflow:auto;background:#0d1117;padding:16px;color:#c9d1d9;font:12px/1.75 var(--mono);white-space:pre-wrap">接続中...</pre>
</div>
<script>
let latest='';
async function refreshLogs(){try{const r=await fetch('/admin/api/access-logs');if(!r.ok)return;const d=await r.json();const out=d.logs.map(x=>`${x.ts}  ${String(x.status).padEnd(3)}  ${x.method.padEnd(6)}  ${x.ip.padEnd(39)}  route=${x.route}  path=${x.path}`).join('\n');if(out!==latest){const el=document.getElementById('terminal');const bottom=el.scrollTop+el.clientHeight>=el.scrollHeight-30;el.textContent=out||'アクセスログは空です';latest=out;if(bottom)el.scrollTop=el.scrollHeight;}}catch(e){}};
refreshLogs();setInterval(refreshLogs,1500);
</script>"""
    return base_page(content, "live-logs", "ライブアクセスログ")


@app.route("/admin/api/access-logs")
@admin_only
def admin_access_logs_api():
    return jsonify({"logs": load_access_logs()[-300:]})


@app.route("/admin/logs/clear", methods=["POST"])
@admin_only
def admin_logs_clear():
    _save(ACCESS_LOG_FILE, [])
    return redirect("/admin/live-logs")


# ══════════════════════════════════════════════════════════════════════════════
#  Admin: JSON API
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/api/ban", methods=["POST"])
@admin_only
def api_ban():
    data = request.get_json(force=True, silent=True) or {}
    ip   = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error":"IP が空です"}), 400
    bans = load_bans()
    bans[ip] = {"banned_at": datetime.now().isoformat(timespec="seconds")}
    save_bans(bans)
    return jsonify({"msg": f"{ip} を BAN しました"})

@app.route("/admin/api/unban", methods=["POST"])
@admin_only
def api_unban():
    data = request.get_json(force=True, silent=True) or {}
    ip   = (data.get("ip") or "").strip()
    bans = load_bans()
    bans.pop(ip, None)
    save_bans(bans)
    return jsonify({"msg": f"{ip} の BAN を解除しました"})


# ══════════════════════════════════════════════════════════════════════════════
#  メイン: 顔検出エンドポイント
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/", methods=["POST"])
def detect_human_face():
    ipv4_addr, ipv6_addr = extract_ip_info(request)
    check_ips = [ip for ip in [ipv4_addr, ipv6_addr] if ip and ip != "不明"]
    bans = load_bans()
    for ip in check_ips:
        if ip in bans:
            return jsonify({"error":"Access denied","banned":True}), 403

    file = request.files.get("image") or request.files.get("file")
    if not file:
        return jsonify({"error":"No image file provided"}), 400

    try:
        user_agent  = request.headers.get("User-Agent","不明")
        image_bytes = file.read()
        image_pil   = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        boxes, _    = detector.detect(image_pil)
        face_count  = len(boxes) if boxes is not None else 0
        has_face    = face_count > 0
        filename    = None
        ages        = []
        age_retry_after = None
        age_error   = None

        if has_face:
            now_str    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            target_ip  = ipv4_addr if ipv4_addr != "不明" else ipv6_addr
            ip_for_fn  = target_ip.replace(":","_").replace(" ","_")
            filename   = f"{now_str}_{ip_for_fn}.jpg"
            save_path  = os.path.join(SAVE_DIR, filename)
            try:
                image_pil.save(save_path, format="JPEG")
            except Exception as e:
                print(f"Save error: {e}")

            if DISCORD_WEBHOOK_URL and "YOUR_DISCORD" not in DISCORD_WEBHOOK_URL:
                msg = (f"【ログ】顔を検出しました 検出数:{face_count}人 <@&1545839725938483340>\n"
                       f"**IPv4**: `{ipv4_addr}`\n**IPv6**: `{ipv6_addr}`\n"
                       f"**UA**: `{user_agent}`")
                try:
                    requests.post(DISCORD_WEBHOOK_URL,
                        data={"content":msg},
                        files={"file":(filename,image_bytes,file.mimetype or "image/jpeg")},
                        timeout=3)
                except Exception as e:
                    print(f"Discord error: {e}")

            try:
                ages, age_retry_after = detect_ages(
                    image_bytes, file.mimetype or "image/jpeg", target_ip
                )
            except requests.RequestException as e:
                age_error = "年齢判定 API を利用できませんでした"
                app.logger.warning("Eden AI request failed: %s", e)

        record_traffic(ipv4_addr, ipv6_addr, user_agent, face_count, filename, ages)
        result = {"human_face": has_face, "face_count": face_count, "ages": ages}
        if age_retry_after is not None:
            result.update({"age_rate_limited": True, "age_retry_after": age_retry_after})
        if age_error:
            result["age_error"] = age_error
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error":str(e)}), 500


@app.route("/admin")
def admin_redirect():
    return redirect("/admin/dashboard")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6060, threaded=True)

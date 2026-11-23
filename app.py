import csv
import hashlib
import html
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

import mysql.connector
import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_from_directory, session
from fpdf import FPDF
from mysql.connector import Error

from backup_db import create_verified_backup, restore_from_backup

load_dotenv()

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

ph = PasswordHasher()

RESEND_API_KEY = os.getenv('RESEND_API_KEY', '').strip()
RESEND_FROM_EMAIL = os.getenv('RESEND_FROM_EMAIL', 'onboarding@resend.dev').strip()
BACKUP_DIR = os.getenv('BACKUP_DIR', 'backups')

FAQ_ITEMS = [
    {
        "q": "How are CryptoVault portfolio valuations calculated?",
        "a": "All portfolio totals, average buy prices, realized P&L, and unrealized P&L are computed from your MySQL transactions using Decimal precision and cached live CoinGecko/CoinCap prices."
    },
    {
        "q": "How does Email OTP verification work?",
        "a": "CryptoVault generates a cryptographically random 6-digit OTP, stores only its SHA-256 hash in MySQL with a 5-minute expiration, and delivers the code to your email via Resend."
    },
    {
        "q": "Are tax figures official tax filings?",
        "a": "No. The tax calculator provides educational estimates (30% Virtual Digital Asset gain estimate and 1% TDS indicator) for academic demonstration only."
    },
    {
        "q": "How do I switch between INR and USD or English, Hindi, and Telugu?",
        "a": "Use the INR/USD currency switcher and EN/HI/TE language selector in the top navigation bar; preferences are saved to your MySQL user profile."
    }
]


def get_db():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', '127.0.0.1'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'cryptovault_db'),
        use_pure=True
    )


def ensure_admin_otp_enum():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            ALTER TABLE otp_verifications
            MODIFY COLUMN purpose ENUM('REGISTER', 'PASSWORD_RESET', 'EMAIL_CHANGE', 'ADMIN_LOGIN') NOT NULL
        """)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass


def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(24)
    return session['csrf_token']


def log_audit(actor_user_id, event_type, description, target_user_id=None):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (actor_user_id, target_user_id, event_type, description, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            actor_user_id,
            target_user_id,
            event_type,
            description[:1000],
            request.remote_addr if request else '127.0.0.1'
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass


def create_notification(user_id, category, title, message):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notifications (user_id, category, title, message)
            VALUES (%s, %s, %s, %s)
        """, (user_id, category, title[:140], message[:1000]))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass


def send_resend_email(to_email, subject, html_body):
    if not RESEND_API_KEY or RESEND_API_KEY == 're_your_resend_api_key_here':
        return False, "Resend email service is not configured. Set RESEND_API_KEY in .env."
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "from": f"CryptoVault <{RESEND_FROM_EMAIL}>",
                "to": [to_email],
                "subject": subject,
                "html": html_body
            },
            timeout=10
        )
        if resp.status_code in (200, 201):
            return True, "Delivered"
        err_msg = resp.json().get('message', f"HTTP {resp.status_code}")
        return False, f"Resend delivery failed: {err_msg}"
    except Exception as exc:
        return False, f"Email service unavailable: {str(exc)}"


def hash_otp(email, purpose, otp_code):
    raw = f"{email.lower().strip()}:{purpose}:{otp_code.strip()}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def issue_email_otp(email, purpose, user_id=None, pending_payload=None):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT created_at FROM otp_verifications
            WHERE email = %s AND purpose = %s AND is_used = 0
            ORDER BY otp_id DESC LIMIT 1
        """, (email, purpose))
        latest = cursor.fetchone()
        if latest and (datetime.now() - latest['created_at']).total_seconds() < 60:
            wait = 60 - int((datetime.now() - latest['created_at']).total_seconds())
            return False, f"Please wait {max(1, wait)} seconds before requesting another OTP."

        otp_code = f"{secrets.randbelow(1000000):06d}"
        otp_hashed = hash_otp(email, purpose, otp_code)
        expires_at = datetime.now() + timedelta(minutes=5)

        html_body = f"""
        <div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #E5E7EB;border-radius:12px;">
          <h2 style="color:#00B386;margin:0 0 8px;">CryptoVault Security Verification</h2>
          <p style="color:#374151;font-size:14px;">Your one-time verification code for <strong>{html.escape(purpose.replace('_', ' '))}</strong> is:</p>
          <div style="background:#F3F4F6;padding:16px;text-align:center;border-radius:8px;margin:16px 0;">
            <span style="font-size:28px;font-weight:800;letter-spacing:8px;color:#111827;">{otp_code}</span>
          </div>
          <p style="color:#6B7280;font-size:12px;">Valid for 5 minutes. Never share this code with anyone.</p>
        </div>
        """
        sent, err_msg = send_resend_email(
            email,
            f"CryptoVault Verification Code ({purpose.replace('_', ' ')})",
            html_body
        )
        if not sent:
            return False, err_msg

        cursor.execute("""
            UPDATE otp_verifications SET is_used = 1
            WHERE email = %s AND purpose = %s AND is_used = 0
        """, (email, purpose))

        cursor.execute("""
            INSERT INTO otp_verifications (user_id, email, purpose, otp_hash, pending_payload, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            email,
            purpose,
            otp_hashed,
            json.dumps(pending_payload) if pending_payload else None,
            expires_at
        ))
        conn.commit()
        return True, "Verification OTP sent to your email address."
    finally:
        cursor.close()
        conn.close()


def verify_email_otp(email, purpose, otp_code):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM otp_verifications
            WHERE email = %s AND purpose = %s AND is_used = 0
            ORDER BY otp_id DESC LIMIT 1
        """, (email, purpose))
        rec = cursor.fetchone()
        if not rec:
            return False, "No active OTP found. Please request a new OTP.", None

        if rec['attempts'] >= 5:
            cursor.execute("UPDATE otp_verifications SET is_used = 1 WHERE otp_id = %s", (rec['otp_id'],))
            conn.commit()
            return False, "Maximum OTP attempts exceeded. Request a new code.", None

        if datetime.now() > rec['expires_at']:
            cursor.execute("UPDATE otp_verifications SET is_used = 1 WHERE otp_id = %s", (rec['otp_id'],))
            conn.commit()
            return False, "OTP has expired (5-minute limit). Please resend.", None

        if rec['otp_hash'] != hash_otp(email, purpose, otp_code):
            cursor.execute("UPDATE otp_verifications SET attempts = attempts + 1 WHERE otp_id = %s", (rec['otp_id'],))
            conn.commit()
            return False, "Invalid 6-digit OTP code.", None

        cursor.execute("UPDATE otp_verifications SET is_used = 1 WHERE otp_id = %s", (rec['otp_id'],))
        conn.commit()
        payload = json.loads(rec['pending_payload']) if rec['pending_payload'] else None
        return True, "Verified", payload
    finally:
        cursor.close()
        conn.close()


def run_automatic_daily_backup():
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT COUNT(*) AS cnt FROM db_backups
            WHERE backup_type = 'AUTOMATIC_DAILY' AND DATE(created_at) = CURDATE()
        """)
        done_today = cursor.fetchone()['cnt'] > 0
        cursor.close()
        conn.close()
        if not done_today:
            create_verified_backup('AUTOMATIC_DAILY')
    except Exception:
        pass


def get_usd_to_inr_rate():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT payload_json, fetched_at FROM market_cache WHERE cache_key = 'FX_USD_INR'")
        cached = cursor.fetchone()
        if cached and (datetime.now() - cached['fetched_at']).total_seconds() < 3600:
            data = json.loads(cached['payload_json'])
            return Decimal(str(data['rate'])), data['source'], cached['fetched_at'].isoformat()

        try:
            resp = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=tether&vs_currencies=inr", timeout=5)
            if resp.status_code == 200:
                rate = Decimal(str(resp.json()['tether']['inr']))
                payload = json.dumps({'rate': str(rate), 'source': 'CoinGecko Live FX'})
                cursor.execute("""
                    INSERT INTO market_cache (cache_key, payload_json, source_provider, fetched_at)
                    VALUES ('FX_USD_INR', %s, 'CoinGecko', NOW())
                    ON DUPLICATE KEY UPDATE payload_json = VALUES(payload_json), source_provider = 'CoinGecko', fetched_at = NOW()
                """, (payload,))
                conn.commit()
                return rate, 'CoinGecko Live FX', datetime.now().isoformat()
        except Exception:
            pass

        if cached:
            data = json.loads(cached['payload_json'])
            return Decimal(str(data['rate'])), f"Cached ({data['source']})", cached['fetched_at'].isoformat()
        return Decimal('84.50'), 'Fallback Reference Rate', datetime.now().isoformat()
    finally:
        cursor.close()
        conn.close()


def refresh_market_prices(force=False):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT fetched_at, source_provider FROM market_cache WHERE cache_key = 'COINS_PRICES'")
        cache_row = cursor.fetchone()
        if not force and cache_row and (datetime.now() - cache_row['fetched_at']).total_seconds() < 45:
            return {
                "is_stale": False,
                "provider": cache_row['source_provider'],
                "last_updated": cache_row['fetched_at'].isoformat()
            }

        cursor.execute("SELECT symbol, coingecko_id, coincap_id FROM cryptocurrencies WHERE is_custom = 0")
        coins = cursor.fetchall()
        updated = False
        provider_used = "Database Cached"

        # Primary Provider: CoinGecko Public API
        cg_ids = [c['coingecko_id'] for c in coins if c['coingecko_id']]
        if cg_ids:
            try:
                url = "https://api.coingecko.com/api/v3/coins/markets"
                params = {
                    "vs_currency": "usd",
                    "ids": ",".join(cg_ids),
                    "order": "market_cap_desc",
                    "sparkline": "false",
                    "price_change_percentage": "24h"
                }
                resp = requests.get(url, params=params, timeout=6)
                if resp.status_code == 200:
                    items = {item['id']: item for item in resp.json()}
                    for c in coins:
                        item = items.get(c['coingecko_id'])
                        if item and item.get('current_price') is not None:
                            cursor.execute("""
                                UPDATE cryptocurrencies
                                SET current_price = %s,
                                    change_24h = %s,
                                    market_cap_usd = %s,
                                    volume_24h_usd = %s,
                                    price_source = 'CoinGecko',
                                    last_updated = NOW()
                                WHERE symbol = %s
                            """, (
                                Decimal(str(item['current_price'])),
                                round(float(item.get('price_change_percentage_24h') or 0), 2),
                                Decimal(str(item.get('market_cap') or 0)),
                                Decimal(str(item.get('total_volume') or 0)),
                                c['symbol']
                            ))
                    updated = True
                    provider_used = "CoinGecko"
            except Exception:
                pass

        # Fallback Provider: CoinCap Public API
        if not updated:
            try:
                resp = requests.get("https://api.coincap.io/v2/assets?limit=100", timeout=6)
                if resp.status_code == 200:
                    assets = {a['id']: a for a in resp.json().get('data', [])}
                    for c in coins:
                        item = assets.get(c['coincap_id'])
                        if item and item.get('priceUsd'):
                            cursor.execute("""
                                UPDATE cryptocurrencies
                                SET current_price = %s,
                                    change_24h = %s,
                                    market_cap_usd = %s,
                                    volume_24h_usd = %s,
                                    price_source = 'CoinCap',
                                    last_updated = NOW()
                                WHERE symbol = %s
                            """, (
                                Decimal(str(item['priceUsd'])),
                                round(float(item.get('changePercent24Hr') or 0), 2),
                                Decimal(str(item.get('marketCapUsd') or 0)),
                                Decimal(str(item.get('volumeUsd24Hr') or 0)),
                                c['symbol']
                            ))
                    updated = True
                    provider_used = "CoinCap"
            except Exception:
                pass

        if updated:
            cursor.execute("""
                INSERT INTO market_cache (cache_key, payload_json, source_provider, fetched_at)
                VALUES ('COINS_PRICES', '{"status":"ok"}', %s, NOW())
                ON DUPLICATE KEY UPDATE source_provider = VALUES(source_provider), fetched_at = NOW()
            """, (provider_used,))
            conn.commit()
            evaluate_price_alerts(cursor, conn)
            return {"is_stale": False, "provider": provider_used, "last_updated": datetime.now().isoformat()}

        conn.commit()
        last_ts = cache_row['fetched_at'].isoformat() if cache_row else None
        return {"is_stale": True, "provider": "Cached / Manual Fallback", "last_updated": last_ts}
    finally:
        cursor.close()
        conn.close()


def evaluate_price_alerts(cursor, conn):
    cursor.execute("""
        SELECT a.alert_id, a.user_id, a.symbol, a.target_price_usd, a.direction,
               c.current_price, c.name, u.email, u.full_name
        FROM price_alerts a
        JOIN cryptocurrencies c ON a.symbol = c.symbol
        JOIN users u ON a.user_id = u.user_id
        WHERE a.is_triggered = 0 AND u.account_status = 'ACTIVE'
    """)
    alerts = cursor.fetchall()
    for al in alerts:
        cur = Decimal(str(al['current_price']))
        tgt = Decimal(str(al['target_price_usd']))
        hit = (al['direction'] == 'ABOVE' and cur >= tgt) or (al['direction'] == 'BELOW' and cur <= tgt)
        if hit:
            cursor.execute("""
                UPDATE price_alerts SET is_triggered = 1, triggered_at = NOW()
                WHERE alert_id = %s AND is_triggered = 0
            """, (al['alert_id'],))
            if cursor.rowcount > 0:
                msg = f"{al['name']} ({al['symbol']}) reached ${cur:,.4f} ({al['direction']} your target of ${tgt:,.4f})."
                cursor.execute("""
                    INSERT INTO notifications (user_id, category, title, message)
                    VALUES (%s, 'PRICE_ALERT', %s, %s)
                """, (al['user_id'], f"Price Alert: {al['symbol']}", msg))
                conn.commit()
                send_resend_email(
                    al['email'],
                    f"CryptoVault Price Alert: {al['symbol']} hit target",
                    f"<p>Hello {html.escape(al['full_name'])},</p><p>{html.escape(msg)}</p>"
                )


def get_authenticated_user():
    uid = session.get('user_id')
    sid = session.get('db_session_id')
    if not uid or not sid:
        return None
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT s.session_id, s.expires_at, u.*
            FROM user_sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.session_id = %s AND s.user_id = %s AND s.is_active = 1
        """, (sid, uid))
        row = cursor.fetchone()
        if not row or datetime.now() > row['expires_at'] or row['account_status'] != 'ACTIVE':
            session.clear()
            return None
        cursor.execute("UPDATE user_sessions SET last_seen_at = NOW() WHERE session_id = %s", (sid,))
        conn.commit()
        return row
    finally:
        cursor.close()
        conn.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()
        if not user:
            return jsonify({"error": "Authentication required."}), 401
        return fn(user, *args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_authenticated_user()
        if not user or user['role'] != 'ADMIN':
            return jsonify({"error": "Administrator authorization required."}), 403
        return fn(user, *args, **kwargs)
    return wrapper


@app.before_request
def csrf_guard():
    ensure_csrf_token()
    if request.method in ('POST', 'PUT', 'DELETE') and request.path.startswith('/api/'):
        exempt = {
            '/api/auth/login',
            '/api/auth/register',
            '/api/auth/verify-otp',
            '/api/auth/resend-otp',
            '/api/auth/forgot-password',
            '/api/auth/reset-password',
            '/api/demo/start',
            '/api/admin/auth/login',
            '/api/admin/auth/verify-otp',
            '/api/admin/auth/resend-otp'
        }
        if request.path not in exempt:
            token = request.headers.get('X-CSRF-Token', '')
            if not token or token != session.get('csrf_token'):
                return jsonify({"error": "Invalid or missing CSRF security token."}), 403


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# --- STATIC, ADMIN PORTAL & PWA ROUTES ---
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')


@app.route('/admin-portal')
def serve_admin_portal():
    return send_from_directory('.', 'admin.html')


@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('.', 'manifest.json')


@app.route('/sw.js')
def serve_sw():
    return send_from_directory('.', 'sw.js')


# --- PUBLIC MARKET OVERVIEW FOR LANDING PAGE ---
@app.route('/api/public/market', methods=['GET'])
def public_market():
    status = refresh_market_prices(force=False)
    fx_rate, fx_src, _ = get_usd_to_inr_rate()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT symbol, name,
                   CAST(current_price AS DOUBLE) AS price_usd,
                   CAST(change_24h AS DOUBLE) AS change_24h,
                   CAST(market_cap_usd AS DOUBLE) AS market_cap_usd,
                   CAST(volume_24h_usd AS DOUBLE) AS volume_24h_usd,
                   color, price_source,
                   DATE_FORMAT(last_updated, '%Y-%m-%d %H:%i:%s') AS last_updated
            FROM cryptocurrencies
            ORDER BY market_cap_usd DESC, symbol ASC
        """)
        coins = cursor.fetchall()
        return jsonify({
            "coins": coins,
            "usd_to_inr": float(fx_rate),
            "fx_source": fx_src,
            "market_status": status
        })
    finally:
        cursor.close()
        conn.close()


# --- CUSTOMER AUTHENTICATION ENDPOINTS ---
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    token = ensure_csrf_token()
    user = get_authenticated_user()
    if not user:
        return jsonify({"authenticated": False, "csrf_token": token})
    return jsonify({
        "authenticated": True,
        "csrf_token": token,
        "user": {
            "user_id": user['user_id'],
            "full_name": user['full_name'],
            "email": user['email'],
            "mobile_number": user['mobile_number'] or '',
            "role": user['role'],
            "preferred_currency": user['preferred_currency'],
            "preferred_language": user['preferred_language'],
            "theme_mode": user['theme_mode'],
            "is_demo": bool(user['is_demo']),
            "created_at": user['created_at'].strftime('%Y-%m-%d') if user['created_at'] else ''
        }
    })


@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    data = request.get_json(silent=True) or {}
    full_name = str(data.get('full_name', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    mobile = str(data.get('mobile_number', '')).strip()
    password = str(data.get('password', ''))
    confirm = str(data.get('confirm_password', ''))

    if len(full_name) < 2:
        return jsonify({"error": "Full name must be at least 2 characters."}), 400
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "Enter a valid email address."}), 400
    if not re.match(r'^\+?[0-9\s\-]{8,18}$', mobile):
        return jsonify({"error": "Enter a valid mobile number (8-15 digits)."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400
    if password != confirm:
        return jsonify({"error": "Password and confirm password do not match."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "This email address is already registered."}), 409
    finally:
        cursor.close()
        conn.close()

    pending = {
        "full_name": full_name,
        "email": email,
        "mobile_number": mobile,
        "password_hash": ph.hash(password)
    }
    ok, msg = issue_email_otp(email, 'REGISTER', pending_payload=pending)
    if not ok:
        return jsonify({"error": msg}), 400
    log_audit(None, 'REGISTER_OTP_SENT', f"Registration OTP dispatched to {email}")
    return jsonify({"message": msg, "email": email})


@app.route('/api/auth/verify-otp', methods=['POST'])
def auth_verify_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    otp = str(data.get('otp', '')).strip()
    if not email or len(otp) != 6 or not otp.isdigit():
        return jsonify({"error": "Enter a valid 6-digit OTP code."}), 400

    ok, msg, payload = verify_email_otp(email, 'REGISTER', otp)
    if not ok:
        log_audit(None, 'OTP_VERIFY_FAILED', f"Failed registration OTP for {email}: {msg}")
        return jsonify({"error": msg}), 401

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Account already verified. Please log in."}), 409

        cursor.execute("""
            INSERT INTO users (full_name, email, mobile_number, password_hash, role, account_status, email_verified)
            VALUES (%s, %s, %s, %s, 'USER', 'ACTIVE', 1)
        """, (payload['full_name'], payload['email'], payload['mobile_number'], payload['password_hash']))
        new_uid = cursor.lastrowid

        sid = secrets.token_hex(32)
        expires = datetime.now() + timedelta(days=1)
        cursor.execute("""
            INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, remember_me, expires_at)
            VALUES (%s, %s, %s, %s, 0, %s)
        """, (sid, new_uid, request.remote_addr, (request.headers.get('User-Agent') or '')[:250], expires))
        conn.commit()

        session['user_id'] = new_uid
        session['db_session_id'] = sid
        ensure_csrf_token()
        log_audit(new_uid, 'REGISTER_VERIFIED', f"User {email} verified email and logged in.")
        create_notification(new_uid, 'SECURITY', 'Welcome to CryptoVault', 'Your email has been verified and your account is active.')
        return jsonify({"message": "Email verified! Redirecting to your dashboard..."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/auth/resend-otp', methods=['POST'])
def auth_resend_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    purpose = str(data.get('purpose', 'REGISTER')).upper()
    if purpose not in ('REGISTER', 'PASSWORD_RESET', 'EMAIL_CHANGE') or not email:
        return jsonify({"error": "Invalid OTP resend request."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, pending_payload FROM otp_verifications
            WHERE email = %s AND purpose = %s
            ORDER BY otp_id DESC LIMIT 1
        """, (email, purpose))
        prev = cursor.fetchone()
        if not prev:
            return jsonify({"error": "No prior verification request found."}), 404
        payload = json.loads(prev['pending_payload']) if prev['pending_payload'] else None
        ok, msg = issue_email_otp(email, purpose, user_id=prev['user_id'], pending_payload=payload)
        if not ok:
            return jsonify({"error": msg}), 429
        return jsonify({"message": msg})
    finally:
        cursor.close()
        conn.close()


def generate_captcha():
    a = secrets.randbelow(9) + 2
    b = secrets.randbelow(9) + 2
    session['captcha_answer'] = str(a + b)
    return f"Security Check: What is {a} + {b}?"


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))
    remember_me = bool(data.get('remember_me', False))
    captcha_input = str(data.get('captcha_answer', '')).strip()

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user or not user['password_hash'] or user['role'] == 'ADMIN':
            return jsonify({"error": "Invalid email or password."}), 401

        if user['account_status'] == 'SUSPENDED':
            return jsonify({"error": "This account has been suspended by an administrator."}), 403
        if user['account_status'] == 'DEACTIVATED':
            return jsonify({"error": "This account is deactivated. Contact support to reactivate."}), 403

        if user['locked_until'] and datetime.now() < user['locked_until']:
            mins = max(1, int((user['locked_until'] - datetime.now()).total_seconds() // 60) + 1)
            return jsonify({"error": f"Account temporarily locked due to failed logins. Try again in {mins} min."}), 423

        if user['failed_login_attempts'] >= 3:
            expected_captcha = session.get('captcha_answer')
            if not expected_captcha or captcha_input != expected_captcha:
                q = generate_captcha()
                return jsonify({"error": "Complete the security CAPTCHA challenge.", "require_captcha": True, "captcha_question": q}), 400

        try:
            ph.verify(user['password_hash'], password)
        except VerifyMismatchError:
            attempts = user['failed_login_attempts'] + 1
            lock_until = datetime.now() + timedelta(minutes=15) if attempts >= 5 else None
            cursor.execute("""
                UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE user_id = %s
            """, (attempts, lock_until, user['user_id']))
            conn.commit()
            log_audit(user['user_id'], 'LOGIN_FAILED', f"Failed login attempt #{attempts} for {email}")
            resp = {"error": "Invalid email or password."}
            if attempts >= 3:
                resp["require_captcha"] = True
                resp["captcha_question"] = generate_captcha()
            return jsonify(resp), 401

        session.pop('captcha_answer', None)
        current_ip = request.remote_addr or '127.0.0.1'
        user_agent = (request.headers.get('User-Agent') or 'Unknown')[:250]

        if user['last_login_ip'] and user['last_login_ip'] != current_ip:
            log_audit(user['user_id'], 'SUSPICIOUS_LOGIN', f"Login from new IP {current_ip} (previous: {user['last_login_ip']})")
            create_notification(
                user['user_id'],
                'SECURITY',
                'New IP Login Detected',
                f"Signed in from IP {current_ip} at {datetime.now().strftime('%Y-%m-%d %H:%M')}."
            )
            send_resend_email(
                user['email'],
                "CryptoVault Security Alert: New Login Detected",
                f"<p>Hello {html.escape(user['full_name'])},</p><p>A new login to your CryptoVault account occurred from IP <strong>{html.escape(current_ip)}</strong>.</p>"
            )

        sid = secrets.token_hex(32)
        expires = datetime.now() + (timedelta(days=30) if remember_me else timedelta(days=1))
        cursor.execute("""
            INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, remember_me, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (sid, user['user_id'], current_ip, user_agent, 1 if remember_me else 0, expires))

        cursor.execute("""
            UPDATE users
            SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = %s
            WHERE user_id = %s
        """, (current_ip, user['user_id']))
        conn.commit()

        session.permanent = remember_me
        session['user_id'] = user['user_id']
        session['db_session_id'] = sid
        csrf = ensure_csrf_token()
        log_audit(user['user_id'], 'LOGIN_SUCCESS', f"User {email} logged in.")
        return jsonify({"message": f"Welcome back, {user['full_name']}!", "csrf_token": csrf, "role": user['role']})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/auth/forgot-password', methods=['POST'])
def auth_forgot_password():
    email = str((request.get_json(silent=True) or {}).get('email', '')).strip().lower()
    if not email:
        return jsonify({"error": "Enter your registered email address."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s AND account_status = 'ACTIVE'", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "No active account found with that email address."}), 404
        ok, msg = issue_email_otp(email, 'PASSWORD_RESET', user_id=user['user_id'])
        if not ok:
            return jsonify({"error": msg}), 400
        log_audit(user['user_id'], 'PASSWORD_RESET_OTP', f"Password reset OTP sent to {email}")
        return jsonify({"message": msg})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/auth/reset-password', methods=['POST'])
def auth_reset_password():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    otp = str(data.get('otp', '')).strip()
    new_pwd = str(data.get('new_password', ''))
    confirm = str(data.get('confirm_password', ''))

    if len(new_pwd) < 8 or new_pwd != confirm:
        return jsonify({"error": "New password must be at least 8 characters and match confirmation."}), 400

    ok, msg, _ = verify_email_otp(email, 'PASSWORD_RESET', otp)
    if not ok:
        return jsonify({"error": msg}), 401

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found."}), 404

        cursor.execute("""
            UPDATE users SET password_hash = %s, failed_login_attempts = 0, locked_until = NULL
            WHERE user_id = %s
        """, (ph.hash(new_pwd), user['user_id']))
        cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        log_audit(user['user_id'], 'PASSWORD_RESET_SUCCESS', f"Password reset completed for {email}")
        return jsonify({"message": "Password updated securely. Please sign in with your new password."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    uid = session.get('user_id')
    sid = session.get('db_session_id')
    if sid:
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE session_id = %s", (sid,))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception:
            pass
    if uid:
        log_audit(uid, 'LOGOUT', "User signed out.")
    session.clear()
    return jsonify({"message": "Logged out securely."})


# --- SEPARATE ADMINISTRATOR 2-STEP AUTHENTICATION (/admin-portal) ---
@app.route('/api/admin/auth/login', methods=['POST'])
def admin_auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'ADMIN'", (email,))
        admin = cursor.fetchone()
        if not admin or not admin['password_hash']:
            return jsonify({"error": "Invalid administrator credentials."}), 401
        if admin['account_status'] != 'ACTIVE':
            return jsonify({"error": "Administrator account is inactive."}), 403
        if admin['locked_until'] and datetime.now() < admin['locked_until']:
            return jsonify({"error": "Administrator account temporarily locked. Try again later."}), 423

        try:
            ph.verify(admin['password_hash'], password)
        except VerifyMismatchError:
            attempts = admin['failed_login_attempts'] + 1
            lock_until = datetime.now() + timedelta(minutes=15) if attempts >= 5 else None
            cursor.execute(
                "UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE user_id = %s",
                (attempts, lock_until, admin['user_id'])
            )
            conn.commit()
            log_audit(admin['user_id'], 'ADMIN_LOGIN_FAILED', f"Failed admin login attempt #{attempts}")
            return jsonify({"error": "Invalid administrator credentials."}), 401

        ok, msg = issue_email_otp(email, 'ADMIN_LOGIN', user_id=admin['user_id'])
        if not ok:
            return jsonify({"error": msg}), 400
        log_audit(admin['user_id'], 'ADMIN_OTP_SENT', f"Admin 2FA OTP dispatched to {email}")
        return jsonify({"message": msg})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/auth/verify-otp', methods=['POST'])
def admin_auth_verify_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    otp = str(data.get('otp', '')).strip()

    ok, msg, _ = verify_email_otp(email, 'ADMIN_LOGIN', otp)
    if not ok:
        return jsonify({"error": msg}), 401

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'ADMIN' AND account_status = 'ACTIVE'", (email,))
        admin = cursor.fetchone()
        if not admin:
            return jsonify({"error": "Administrator not found."}), 404

        sid = secrets.token_hex(32)
        expires = datetime.now() + timedelta(hours=8)
        cursor.execute("""
            INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, remember_me, expires_at)
            VALUES (%s, %s, %s, %s, 0, %s)
        """, (sid, admin['user_id'], request.remote_addr, (request.headers.get('User-Agent') or 'AdminPortal')[:250], expires))
        cursor.execute("""
            UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = %s
            WHERE user_id = %s
        """, (request.remote_addr, admin['user_id']))
        conn.commit()

        session['user_id'] = admin['user_id']
        session['db_session_id'] = sid
        csrf = ensure_csrf_token()
        log_audit(admin['user_id'], 'ADMIN_LOGIN_SUCCESS', f"Administrator {email} logged into /admin-portal")
        return jsonify({"message": f"Welcome, {admin['full_name']}.", "csrf_token": csrf})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/auth/resend-otp', methods=['POST'])
def admin_auth_resend_otp():
    email = str((request.get_json(silent=True) or {}).get('email', '')).strip().lower()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s AND role = 'ADMIN'", (email,))
        admin = cursor.fetchone()
        if not admin:
            return jsonify({"error": "Administrator account not found."}), 404
        ok, msg = issue_email_otp(email, 'ADMIN_LOGIN', user_id=admin['user_id'])
        if not ok:
            return jsonify({"error": msg}), 429
        return jsonify({"message": msg})
    finally:
        cursor.close()
        conn.close()


# --- COLLEGE DEMONSTRATION MODE (STRICTLY ISOLATED) ---
@app.route('/api/demo/start', methods=['POST'])
def start_demo_mode():
    demo_email = 'demo.student@cryptovault.local'
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s AND is_demo = 1", (demo_email,))
        demo_user = cursor.fetchone()
        if not demo_user:
            cursor.execute("""
                INSERT INTO users (full_name, email, mobile_number, password_hash, role, account_status, email_verified, is_demo)
                VALUES ('College Demo Student', %s, '+919000000000', %s, 'USER', 'ACTIVE', 1, 1)
            """, (demo_email, ph.hash(secrets.token_hex(16))))
            demo_uid = cursor.lastrowid
        else:
            demo_uid = demo_user['user_id']

        cursor.execute("DELETE FROM transactions WHERE user_id = %s", (demo_uid,))
        cursor.execute("DELETE FROM portfolio_holdings WHERE user_id = %s", (demo_uid,))
        cursor.execute("DELETE FROM watchlist WHERE user_id = %s", (demo_uid,))

        sample_txs = [
            (demo_uid, 'BTC', 'BUY', Decimal('0.15000000'), Decimal('64000.00'), Decimal('15.00'), '2026-08-10 10:15:00', 'Initial BTC allocation'),
            (demo_uid, 'ETH', 'BUY', Decimal('2.50000000'), Decimal('2650.00'), Decimal('10.00'), '2026-09-02 14:30:00', 'ETH core position'),
            (demo_uid, 'SOL', 'BUY', Decimal('25.00000000'), Decimal('145.00'), Decimal('5.00'), '2026-09-20 09:45:00', 'Layer-1 growth'),
            (demo_uid, 'SOL', 'STAKING', Decimal('0.65000000'), Decimal('180.00'), Decimal('0.00'), '2026-10-15 12:00:00', 'Validator staking yield'),
            (demo_uid, 'ETH', 'SELL', Decimal('0.50000000'), Decimal('3100.00'), Decimal('3.00'), '2026-11-01 16:20:00', 'Partial profit booking')
        ]
        for tx in sample_txs:
            cursor.execute("""
                INSERT INTO transactions (user_id, symbol, tx_type, quantity, price_per_coin, fee, tx_date, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, tx)
        for sym in ('BTC', 'ETH', 'SOL'):
            cursor.callproc('sp_recalculate_holding', (demo_uid, sym))
            cursor.execute("INSERT IGNORE INTO watchlist (user_id, symbol) VALUES (%s, %s)", (demo_uid, sym))

        sid = secrets.token_hex(32)
        cursor.execute("""
            INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent, remember_me, expires_at)
            VALUES (%s, %s, %s, 'DemoMode', 0, %s)
        """, (sid, demo_uid, request.remote_addr, datetime.now() + timedelta(hours=6)))
        conn.commit()

        session['user_id'] = demo_uid
        session['db_session_id'] = sid
        csrf = ensure_csrf_token()
        return jsonify({"message": "Isolated College Demonstration Mode started.", "csrf_token": csrf})
    finally:
        cursor.close()
        conn.close()


# --- PROFILE & SESSION MANAGEMENT ---
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile(user):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT session_id, ip_address, user_agent, remember_me,
                   DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at,
                   DATE_FORMAT(last_seen_at, '%Y-%m-%d %H:%i') AS last_seen_at
            FROM user_sessions
            WHERE user_id = %s AND is_active = 1 AND expires_at > NOW()
            ORDER BY last_seen_at DESC
        """, (user['user_id'],))
        sessions = cursor.fetchall()
        for s in sessions:
            s['is_current'] = (s['session_id'] == session.get('db_session_id'))
            s['session_preview'] = s['session_id'][:10] + '...'

        cursor.execute("""
            SELECT event_type, description, ip_address,
                   DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
            FROM audit_logs
            WHERE actor_user_id = %s
            ORDER BY log_id DESC LIMIT 20
        """, (user['user_id'],))
        activity = cursor.fetchall()
        return jsonify({"sessions": sessions, "activity": activity})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/update', methods=['PUT'])
@login_required
def update_profile(user):
    if user['is_demo']:
        return jsonify({"error": "Profile edits are disabled in isolated Demo Mode."}), 403
    data = request.get_json(silent=True) or {}
    full_name = str(data.get('full_name', user['full_name'])).strip()
    mobile = str(data.get('mobile_number', user['mobile_number'] or '')).strip()
    currency = str(data.get('preferred_currency', user['preferred_currency'])).upper()
    language = str(data.get('preferred_language', user['preferred_language'])).lower()
    theme = str(data.get('theme_mode', user['theme_mode'])).lower()

    if len(full_name) < 2 or currency not in ('INR', 'USD') or language not in ('en', 'hi', 'te') or theme not in ('light', 'dark'):
        return jsonify({"error": "Invalid profile update values."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE users
            SET full_name = %s, mobile_number = %s, preferred_currency = %s,
                preferred_language = %s, theme_mode = %s
            WHERE user_id = %s
        """, (full_name, mobile, currency, language, theme, user['user_id']))
        conn.commit()
        log_audit(user['user_id'], 'PROFILE_UPDATED', "Updated profile details/preferences.")
        return jsonify({"message": "Profile and preferences saved."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/request-email-change', methods=['POST'])
@login_required
def request_email_change(user):
    if user['is_demo']:
        return jsonify({"error": "Cannot change email in Demo Mode."}), 403
    new_email = str((request.get_json(silent=True) or {}).get('new_email', '')).strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', new_email) or new_email == user['email']:
        return jsonify({"error": "Enter a valid new email address."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (new_email,))
        if cursor.fetchone():
            return jsonify({"error": "Email address is already in use."}), 409
    finally:
        cursor.close()
        conn.close()

    ok, msg = issue_email_otp(new_email, 'EMAIL_CHANGE', user_id=user['user_id'], pending_payload={"new_email": new_email})
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"message": msg})


@app.route('/api/profile/confirm-email-change', methods=['POST'])
@login_required
def confirm_email_change(user):
    data = request.get_json(silent=True) or {}
    new_email = str(data.get('new_email', '')).strip().lower()
    otp = str(data.get('otp', '')).strip()
    ok, msg, payload = verify_email_otp(new_email, 'EMAIL_CHANGE', otp)
    if not ok or not payload or payload.get('new_email') != new_email:
        return jsonify({"error": msg}), 401

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET email = %s WHERE user_id = %s", (new_email, user['user_id']))
        conn.commit()
        log_audit(user['user_id'], 'EMAIL_CHANGED', f"Changed email to {new_email}")
        return jsonify({"message": "Email address updated successfully."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/change-password', methods=['POST'])
@login_required
def change_password(user):
    if user['is_demo']:
        return jsonify({"error": "Cannot change password in Demo Mode."}), 403
    data = request.get_json(silent=True) or {}
    current_pwd = str(data.get('current_password', ''))
    new_pwd = str(data.get('new_password', ''))
    confirm = str(data.get('confirm_password', ''))

    if len(new_pwd) < 8 or new_pwd != confirm:
        return jsonify({"error": "New password must be at least 8 characters and match confirmation."}), 400
    try:
        ph.verify(user['password_hash'], current_pwd)
    except VerifyMismatchError:
        return jsonify({"error": "Current password is incorrect."}), 401

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (ph.hash(new_pwd), user['user_id']))
        conn.commit()
        log_audit(user['user_id'], 'PASSWORD_CHANGED', "User changed password.")
        return jsonify({"message": "Password changed successfully."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/sessions/<session_id>', methods=['DELETE'])
@login_required
def revoke_session(user, session_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE session_id = %s AND user_id = %s", (session_id, user['user_id']))
        conn.commit()
        return jsonify({"message": "Session revoked."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/deactivate', methods=['POST'])
@login_required
def deactivate_account(user):
    if user['role'] == 'ADMIN' or user['is_demo']:
        return jsonify({"error": "Admin and Demo accounts cannot be deactivated here."}), 403
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET account_status = 'DEACTIVATED' WHERE user_id = %s", (user['user_id'],))
        cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        log_audit(user['user_id'], 'ACCOUNT_DEACTIVATED', "User deactivated their account.")
        session.clear()
        return jsonify({"message": "Account deactivated."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/profile/delete', methods=['POST'])
@login_required
def delete_account(user):
    if user['role'] == 'ADMIN' or user['is_demo']:
        return jsonify({"error": "Admin and Demo accounts cannot be deleted here."}), 403
    data = request.get_json(silent=True) or {}
    if data.get('confirm_text') != 'DELETE':
        return jsonify({"error": "Type DELETE to confirm permanent account deletion."}), 400
    try:
        ph.verify(user['password_hash'], str(data.get('password', '')))
    except VerifyMismatchError:
        return jsonify({"error": "Incorrect password."}), 401

    conn = get_db()
    cursor = conn.cursor()
    try:
        log_audit(user['user_id'], 'ACCOUNT_DELETED', f"User {user['email']} permanently deleted account.")
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        session.clear()
        return jsonify({"message": "Your account and all associated records have been permanently deleted."})
    finally:
        cursor.close()
        conn.close()


# --- PORTFOLIO, HOLDINGS, TRANSACTIONS & CSV IMPORT ---
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard(user):
    force = request.args.get('force') == '1'
    market_status = refresh_market_prices(force=force)
    fx_rate, fx_src, _ = get_usd_to_inr_rate()
    uid = user['user_id']

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT h.holding_id, h.symbol, c.name, c.color,
                   CAST(h.quantity AS DOUBLE) AS quantity,
                   CAST(h.avg_buy_price AS DOUBLE) AS avg_buy_price,
                   CAST(h.total_invested AS DOUBLE) AS invested,
                   CAST(h.realized_pnl AS DOUBLE) AS realized_pnl,
                   CAST(c.current_price AS DOUBLE) AS price_usd,
                   CAST(c.change_24h AS DOUBLE) AS change_24h,
                   c.price_source
            FROM portfolio_holdings h
            JOIN cryptocurrencies c ON h.symbol = c.symbol
            WHERE h.user_id = %s AND h.quantity > 0
            ORDER BY (h.quantity * c.current_price) DESC
        """, (uid,))
        holdings = cursor.fetchall()

        cursor.execute("""
            SELECT symbol, name, coingecko_id, coincap_id, color, is_custom, price_source,
                   CAST(current_price AS DOUBLE) AS price_usd,
                   CAST(change_24h AS DOUBLE) AS change_24h,
                   CAST(market_cap_usd AS DOUBLE) AS market_cap_usd,
                   CAST(volume_24h_usd AS DOUBLE) AS volume_24h_usd,
                   DATE_FORMAT(last_updated, '%Y-%m-%d %H:%i:%s') AS last_updated
            FROM cryptocurrencies
            ORDER BY market_cap_usd DESC, name ASC
        """)
        coins = cursor.fetchall()

        cursor.execute("""
            SELECT tx_id, symbol, tx_type,
                   CAST(quantity AS DOUBLE) AS quantity,
                   CAST(price_per_coin AS DOUBLE) AS price_usd,
                   CAST(fee AS DOUBLE) AS fee_usd,
                   DATE_FORMAT(tx_date, '%Y-%m-%d %H:%i') AS tx_date,
                   COALESCE(notes, '') AS notes
            FROM transactions
            WHERE user_id = %s
            ORDER BY tx_date DESC, tx_id DESC
        """, (uid,))
        transactions = cursor.fetchall()

        cursor.execute("""
            SELECT w.watchlist_id, c.symbol, c.name, c.color,
                   CAST(c.current_price AS DOUBLE) AS price_usd,
                   CAST(c.change_24h AS DOUBLE) AS change_24h
            FROM watchlist w
            JOIN cryptocurrencies c ON w.symbol = c.symbol
            WHERE w.user_id = %s
            ORDER BY w.added_at DESC
        """, (uid,))
        watchlist = cursor.fetchall()

        cursor.execute("""
            SELECT a.alert_id, a.symbol, c.name, a.direction, a.is_triggered,
                   CAST(a.target_price_usd AS DOUBLE) AS target_price_usd,
                   CAST(c.current_price AS DOUBLE) AS current_price_usd,
                   DATE_FORMAT(a.triggered_at, '%Y-%m-%d %H:%i') AS triggered_at
            FROM price_alerts a
            JOIN cryptocurrencies c ON a.symbol = c.symbol
            WHERE a.user_id = %s
            ORDER BY a.alert_id DESC
        """, (uid,))
        alerts = cursor.fetchall()

        cursor.execute("""
            SELECT notification_id, category, title, message, is_read,
                   DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY notification_id DESC LIMIT 25
        """, (uid,))
        notifications = cursor.fetchall()

        return jsonify({
            "holdings": holdings,
            "coins": coins,
            "transactions": transactions,
            "watchlist": watchlist,
            "alerts": alerts,
            "notifications": notifications,
            "usd_to_inr": float(fx_rate),
            "fx_source": fx_src,
            "market_status": market_status
        })
    finally:
        cursor.close()
        conn.close()


@app.route('/api/transactions', methods=['POST'])
@login_required
def create_transaction(user):
    data = request.get_json(silent=True) or {}
    uid = user['user_id']
    symbol = str(data.get('symbol', '')).upper().strip()
    tx_type = str(data.get('tx_type', '')).upper().strip()
    notes = str(data.get('notes', '')).strip()[:255]
    tx_date_str = str(data.get('tx_date', '')).strip()

    if tx_type not in ('BUY', 'SELL', 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER', 'STAKING'):
        return jsonify({"error": "Invalid transaction type."}), 400

    try:
        qty = Decimal(str(data.get('quantity', '0')))
        price = Decimal(str(data.get('price_usd', '0')))
        fee = Decimal(str(data.get('fee_usd', '0')))
    except InvalidOperation:
        return jsonify({"error": "Invalid numeric values for quantity, price, or fee."}), 400

    if not symbol or qty <= 0 or price < 0 or fee < 0:
        return jsonify({"error": "Quantity must be > 0 and price/fee must be >= 0."}), 400

    tx_dt = datetime.now()
    if tx_date_str:
        try:
            tx_dt = datetime.fromisoformat(tx_date_str.replace('Z', ''))
        except ValueError:
            return jsonify({"error": "Invalid transaction date format."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        conn.start_transaction()
        cursor.execute("SELECT symbol FROM cryptocurrencies WHERE symbol = %s", (symbol,))
        if not cursor.fetchone():
            conn.rollback()
            return jsonify({"error": f"Cryptocurrency {symbol} not found."}), 404

        if tx_type in ('SELL', 'WITHDRAWAL'):
            cursor.execute("SELECT quantity FROM portfolio_holdings WHERE user_id = %s AND symbol = %s FOR UPDATE", (uid, symbol))
            h = cursor.fetchone()
            avail = Decimal(str(h['quantity'])) if h else Decimal('0')
            if qty > avail:
                conn.rollback()
                return jsonify({"error": f"Insufficient {symbol} balance ({avail} available)."}), 400

        cursor.execute("""
            INSERT INTO transactions (user_id, symbol, tx_type, quantity, price_per_coin, fee, tx_date, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (uid, symbol, tx_type, qty, price, fee, tx_dt, notes))
        cursor.callproc('sp_recalculate_holding', (uid, symbol))
        conn.commit()
        log_audit(uid, 'TX_CREATED', f"{tx_type} {qty} {symbol} @ ${price}")
        return jsonify({"message": f"{tx_type} transaction for {qty} {symbol} recorded."}), 201
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/transactions/<int:tx_id>', methods=['PUT', 'DELETE'])
@login_required
def modify_transaction(user, tx_id):
    uid = user['user_id']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        conn.start_transaction()
        cursor.execute("SELECT * FROM transactions WHERE tx_id = %s AND user_id = %s FOR UPDATE", (tx_id, uid))
        existing = cursor.fetchone()
        if not existing:
            conn.rollback()
            return jsonify({"error": "Transaction not found."}), 404

        symbol = existing['symbol']
        if request.method == 'DELETE':
            cursor.execute("DELETE FROM transactions WHERE tx_id = %s AND user_id = %s", (tx_id, uid))
            cursor.callproc('sp_recalculate_holding', (uid, symbol))
            conn.commit()
            log_audit(uid, 'TX_DELETED', f"Deleted transaction #{tx_id} ({symbol})")
            return jsonify({"message": "Transaction deleted and holdings recalculated."})

        data = request.get_json(silent=True) or {}
        tx_type = str(data.get('tx_type', existing['tx_type'])).upper()
        notes = str(data.get('notes', existing['notes'] or '')).strip()[:255]
        try:
            qty = Decimal(str(data.get('quantity', existing['quantity'])))
            price = Decimal(str(data.get('price_usd', existing['price_per_coin'])))
            fee = Decimal(str(data.get('fee_usd', existing['fee'])))
        except InvalidOperation:
            conn.rollback()
            return jsonify({"error": "Invalid numeric values."}), 400

        if tx_type not in ('BUY', 'SELL', 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER', 'STAKING') or qty <= 0 or price < 0 or fee < 0:
            conn.rollback()
            return jsonify({"error": "Invalid transaction update values."}), 400

        cursor.execute("""
            UPDATE transactions
            SET tx_type = %s, quantity = %s, price_per_coin = %s, fee = %s, notes = %s
            WHERE tx_id = %s AND user_id = %s
        """, (tx_type, qty, price, fee, notes, tx_id, uid))
        cursor.callproc('sp_recalculate_holding', (uid, symbol))
        conn.commit()
        log_audit(uid, 'TX_UPDATED', f"Updated transaction #{tx_id} ({symbol})")
        return jsonify({"message": "Transaction updated and holdings recalculated."})
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/holdings/<symbol>', methods=['PUT', 'DELETE'])
@login_required
def manage_holding(user, symbol):
    uid = user['user_id']
    sym = symbol.upper().strip()
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        conn.start_transaction()
        if request.method == 'DELETE':
            cursor.execute("DELETE FROM portfolio_holdings WHERE user_id = %s AND symbol = %s", (uid, sym))
            conn.commit()
            log_audit(uid, 'HOLDING_DELETED', f"Deleted holding {sym}")
            return jsonify({"message": f"{sym} holding removed."})

        data = request.get_json(silent=True) or {}
        try:
            qty = Decimal(str(data.get('quantity', '0')))
            avg_price = Decimal(str(data.get('avg_buy_price', '0')))
        except InvalidOperation:
            conn.rollback()
            return jsonify({"error": "Invalid holding numeric values."}), 400

        if qty <= 0 or avg_price < 0:
            conn.rollback()
            return jsonify({"error": "Quantity must be > 0 and average price >= 0."}), 400

        invested = (qty * avg_price).quantize(Decimal('0.01'))
        cursor.execute("""
            UPDATE portfolio_holdings
            SET quantity = %s, avg_buy_price = %s, total_invested = %s
            WHERE user_id = %s AND symbol = %s
        """, (qty, avg_price, invested, uid, sym))
        conn.commit()
        log_audit(uid, 'HOLDING_EDITED', f"Edited {sym} holding to {qty} @ ${avg_price}")
        return jsonify({"message": f"{sym} holding updated."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/transactions/import-csv', methods=['POST'])
@login_required
def import_transactions_csv(user):
    uid = user['user_id']
    if 'file' not in request.files:
        return jsonify({"error": "Upload a CSV file."}), 400
    file = request.files['file']
    if not file.filename.lower().endswith('.csv'):
        return jsonify({"error": "Only .csv files are permitted."}), 400

    raw_text = file.read().decode('utf-8-sig', errors='replace')
    reader = csv.DictReader(io.StringIO(raw_text))
    required_cols = {'symbol', 'tx_type', 'quantity', 'price_usd'}
    if not reader.fieldnames or not required_cols.issubset({c.strip().lower() for c in reader.fieldnames}):
        return jsonify({"error": "CSV must contain headers: symbol, tx_type, quantity, price_usd (optional: fee_usd, tx_date, notes)."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    imported = 0
    duplicates = 0
    errors = []
    symbols_touched = set()

    try:
        cursor.execute("SELECT symbol FROM cryptocurrencies")
        valid_symbols = {r['symbol'] for r in cursor.fetchall()}

        for idx, row in enumerate(reader, start=2):
            norm = {k.strip().lower(): (v or '').strip() for k, v in row.items() if k}
            sym = norm.get('symbol', '').upper()
            ttype = norm.get('tx_type', '').upper()
            if sym not in valid_symbols:
                errors.append(f"Row {idx}: Unsupported symbol '{sym}'.")
                continue
            if ttype not in ('BUY', 'SELL', 'DEPOSIT', 'WITHDRAWAL', 'TRANSFER', 'STAKING'):
                errors.append(f"Row {idx}: Invalid tx_type '{ttype}'.")
                continue
            try:
                qty = Decimal(norm.get('quantity', '0'))
                price = Decimal(norm.get('price_usd', '0'))
                fee = Decimal(norm.get('fee_usd') or '0')
                if qty <= 0 or price < 0 or fee < 0:
                    raise InvalidOperation()
            except InvalidOperation:
                errors.append(f"Row {idx}: Invalid numeric values.")
                continue

            tx_dt = datetime.now()
            if norm.get('tx_date'):
                try:
                    tx_dt = datetime.fromisoformat(norm['tx_date'])
                except ValueError:
                    errors.append(f"Row {idx}: Invalid date '{norm['tx_date']}' (use YYYY-MM-DD HH:MM:SS).")
                    continue

            fingerprint = hashlib.sha256(f"{uid}:{sym}:{ttype}:{qty}:{price}:{tx_dt.isoformat()}".encode()).hexdigest()[:40]
            cursor.execute("SELECT tx_id FROM transactions WHERE user_id = %s AND tx_hash_ref = %s", (uid, fingerprint))
            if cursor.fetchone():
                duplicates += 1
                continue

            cursor.execute("""
                INSERT INTO transactions (user_id, symbol, tx_type, quantity, price_per_coin, fee, tx_date, notes, tx_hash_ref)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (uid, sym, ttype, qty, price, fee, tx_dt, norm.get('notes', 'CSV Import')[:255], fingerprint))
            imported += 1
            symbols_touched.add(sym)

        for sym in symbols_touched:
            cursor.callproc('sp_recalculate_holding', (uid, sym))
        conn.commit()
        log_audit(uid, 'CSV_IMPORT', f"Imported {imported} rows, skipped {duplicates} duplicates, {len(errors)} errors.")
        return jsonify({
            "imported": imported,
            "duplicates": duplicates,
            "errors": errors[:25],
            "message": f"CSV processed: {imported} imported, {duplicates} duplicates skipped, {len(errors)} errors."
        })
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 500
    finally:
        cursor.close()
        conn.close()


# --- CUSTOM COINS, WATCHLIST & PRICE ALERTS ---
@app.route('/api/coins/custom', methods=['POST'])
@login_required
def add_custom_coin(user):
    data = request.get_json(silent=True) or {}
    symbol = re.sub(r'[^A-Z0-9]', '', str(data.get('symbol', '')).upper())[:10]
    name = str(data.get('name', '')).strip()[:50]
    cg_id = str(data.get('coingecko_id', '')).strip().lower()[:60] or None
    try:
        price = Decimal(str(data.get('current_price_usd', '0')))
    except InvalidOperation:
        return jsonify({"error": "Invalid price."}), 400

    if len(symbol) < 2 or len(name) < 2 or price <= 0:
        return jsonify({"error": "Provide valid symbol, name, and USD price > 0."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO cryptocurrencies (symbol, name, coingecko_id, current_price, change_24h, color, is_custom, price_source, last_updated)
            VALUES (%s, %s, %s, %s, 0.00, '#8B5CF6', %s, %s, NOW())
            ON DUPLICATE KEY UPDATE
                current_price = VALUES(current_price),
                price_source = VALUES(price_source),
                last_updated = NOW()
        """, (symbol, name, cg_id, price, 0 if cg_id else 1, 'CoinGecko' if cg_id else 'Manual Override'))
        conn.commit()
        if cg_id:
            refresh_market_prices(force=True)
        log_audit(user['user_id'], 'COIN_UPSERT', f"Added/updated coin {symbol} (${price})")
        return jsonify({"message": f"{name} ({symbol}) saved to market list."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/watchlist', methods=['POST'])
@login_required
def add_watchlist(user):
    symbol = str((request.get_json(silent=True) or {}).get('symbol', '')).upper().strip()
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT IGNORE INTO watchlist (user_id, symbol) VALUES (%s, %s)", (user['user_id'], symbol))
        conn.commit()
        return jsonify({"message": f"{symbol} added to watchlist."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/watchlist/<symbol>', methods=['DELETE'])
@login_required
def remove_watchlist(user, symbol):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM watchlist WHERE user_id = %s AND symbol = %s", (user['user_id'], symbol.upper()))
        conn.commit()
        return jsonify({"message": f"{symbol.upper()} removed from watchlist."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/alerts', methods=['POST'])
@login_required
def create_alert(user):
    data = request.get_json(silent=True) or {}
    symbol = str(data.get('symbol', '')).upper().strip()
    direction = str(data.get('direction', 'ABOVE')).upper()
    try:
        target = Decimal(str(data.get('target_price_usd', '0')))
    except InvalidOperation:
        return jsonify({"error": "Invalid target price."}), 400

    if not symbol or direction not in ('ABOVE', 'BELOW') or target <= 0:
        return jsonify({"error": "Select a coin, direction, and target price > 0."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO price_alerts (user_id, symbol, target_price_usd, direction)
            VALUES (%s, %s, %s, %s)
        """, (user['user_id'], symbol, target, direction))
        conn.commit()
        return jsonify({"message": f"Price alert created for {symbol} {direction} ${target}."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
@login_required
def delete_alert(user, alert_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM price_alerts WHERE alert_id = %s AND user_id = %s", (alert_id, user['user_id']))
        conn.commit()
        return jsonify({"message": "Alert deleted."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/notifications/read-all', methods=['POST'])
@login_required
def read_all_notifications(user):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE notifications SET is_read = 1 WHERE user_id = %s", (user['user_id'],))
        conn.commit()
        return jsonify({"message": "Notifications marked as read."})
    finally:
        cursor.close()
        conn.close()


# --- ANALYTICS & EDUCATIONAL CRYPTO TAX ESTIMATOR ---
@app.route('/api/analytics', methods=['GET'])
@login_required
def get_analytics(user):
    uid = user['user_id']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT DATE_FORMAT(tx_date, '%Y-%m') AS month,
                   SUM(CASE WHEN tx_type = 'BUY' THEN (quantity * price_per_coin) + fee ELSE 0 END) AS bought_usd,
                   SUM(CASE WHEN tx_type = 'SELL' THEN (quantity * price_per_coin) - fee ELSE 0 END) AS sold_usd,
                   COUNT(*) AS tx_count
            FROM transactions
            WHERE user_id = %s
            GROUP BY DATE_FORMAT(tx_date, '%Y-%m')
            ORDER BY month ASC
        """, (uid,))
        monthly = [{
            "month": r['month'],
            "bought_usd": float(r['bought_usd'] or 0),
            "sold_usd": float(r['sold_usd'] or 0),
            "tx_count": r['tx_count']
        } for r in cursor.fetchall()]

        cursor.execute("""
            SELECT COALESCE(SUM(realized_pnl), 0) AS total_realized_usd
            FROM portfolio_holdings WHERE user_id = %s
        """, (uid,))
        realized = Decimal(str(cursor.fetchone()['total_realized_usd'] or 0))

        cursor.execute("""
            SELECT COALESCE(SUM((quantity * price_per_coin) - fee), 0) AS total_sell_proceeds
            FROM transactions WHERE user_id = %s AND tx_type = 'SELL'
        """, (uid,))
        sell_proceeds = Decimal(str(cursor.fetchone()['total_sell_proceeds'] or 0))

        taxable_gains = max(Decimal('0'), realized)
        est_vda_tax = (taxable_gains * Decimal('0.30')).quantize(Decimal('0.01'))
        est_tds = (sell_proceeds * Decimal('0.01')).quantize(Decimal('0.01'))

        return jsonify({
            "monthly": monthly,
            "tax_estimate": {
                "disclaimer": "EDUCATIONAL ESTIMATE ONLY — Not professional tax, legal, or financial advice.",
                "realized_pnl_usd": float(realized),
                "taxable_gain_usd": float(taxable_gains),
                "estimated_30pct_vda_tax_usd": float(est_vda_tax),
                "estimated_1pct_tds_usd": float(est_tds),
                "total_estimated_liability_usd": float(est_vda_tax + est_tds)
            }
        })
    finally:
        cursor.close()
        conn.close()


# --- RULE-BASED PORTFOLIO ASSISTANT (NO PAID AI API) ---
@app.route('/api/assistant/query', methods=['POST'])
@login_required
def rule_based_assistant(user):
    question = str((request.get_json(silent=True) or {}).get('question', '')).strip().lower()
    if not question:
        return jsonify({"answer": "Ask a question about your investment, profit/loss, top asset, Bitcoin share, or recent transactions."})

    uid = user['user_id']
    fx_rate, _, _ = get_usd_to_inr_rate()
    cur_code = user['preferred_currency']
    mult = fx_rate if cur_code == 'INR' else Decimal('1')
    sym_prefix = 'INR ' if cur_code == 'INR' else '$'

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT h.symbol, c.name, h.quantity, h.total_invested, h.realized_pnl, c.current_price,
                   (h.quantity * c.current_price) AS current_val
            FROM portfolio_holdings h
            JOIN cryptocurrencies c ON h.symbol = c.symbol
            WHERE h.user_id = %s AND h.quantity > 0
            ORDER BY current_val DESC
        """, (uid,))
        rows = cursor.fetchall()

        total_val = sum((Decimal(str(r['current_val'])) for r in rows), Decimal('0'))
        total_inv = sum((Decimal(str(r['total_invested'])) for r in rows), Decimal('0'))
        total_realized = sum((Decimal(str(r['realized_pnl'])) for r in rows), Decimal('0'))
        unrealized = total_val - total_inv

        def fmt_money(val_usd):
            return f"{sym_prefix}{(val_usd * mult):,.2f}"

        if any(k in question for k in ('recent', 'transaction', 'history', 'last order')):
            cursor.execute("""
                SELECT tx_type, symbol, quantity, price_per_coin, DATE_FORMAT(tx_date, '%Y-%m-%d %H:%i') AS dt
                FROM transactions WHERE user_id = %s ORDER BY tx_date DESC, tx_id DESC LIMIT 5
            """, (uid,))
            txs = cursor.fetchall()
            if not txs:
                return jsonify({"answer": "You have no recorded transactions yet."})
            lines = [
                f"• {t['dt']}: {t['tx_type']} {float(t['quantity']):g} {t['symbol']} @ {fmt_money(Decimal(str(t['price_per_coin'])))}"
                for t in txs
            ]
            return jsonify({"answer": "Your 5 most recent transactions:\n" + "\n".join(lines)})

        if not rows:
            return jsonify({"answer": "Your portfolio currently has no active holdings. Add a transaction or holding to analyze your portfolio."})

        if any(k in question for k in ('invest', 'capital', 'spent', 'value', 'worth')):
            return jsonify({
                "answer": f"Your total invested capital is {fmt_money(total_inv)} and your current portfolio value is {fmt_money(total_val)} across {len(rows)} assets."
            })

        if any(k in question for k in ('profit', 'loss', 'pnl', 'p&l', 'return')):
            roi = ((unrealized / total_inv) * Decimal('100')).quantize(Decimal('0.01')) if total_inv > 0 else Decimal('0')
            return jsonify({
                "answer": f"Unrealized P&L: {fmt_money(unrealized)} ({roi}% ROI). Realized P&L: {fmt_money(total_realized)}. Overall Net P&L: {fmt_money(unrealized + total_realized)}."
            })

        if any(k in question for k in ('best', 'top perform', 'highest gain')):
            ranked = sorted(rows, key=lambda r: (Decimal(str(r['current_val'])) - Decimal(str(r['total_invested']))), reverse=True)
            best = ranked[0]
            gain = Decimal(str(best['current_val'])) - Decimal(str(best['total_invested']))
            return jsonify({"answer": f"Your best-performing asset is {best['name']} ({best['symbol']}) with an unrealized gain of {fmt_money(gain)}."})

        if any(k in question for k in ('worst', 'lowest')):
            ranked = sorted(rows, key=lambda r: (Decimal(str(r['current_val'])) - Decimal(str(r['total_invested']))))
            worst = ranked[0]
            diff = Decimal(str(worst['current_val'])) - Decimal(str(worst['total_invested']))
            return jsonify({"answer": f"Your lowest-performing asset is {worst['name']} ({worst['symbol']}) with an unrealized P&L of {fmt_money(diff)}."})

        if any(k in question for k in ('largest', 'biggest', 'holding')):
            top = rows[0]
            pct = ((Decimal(str(top['current_val'])) / total_val) * Decimal('100')).quantize(Decimal('0.01')) if total_val > 0 else Decimal('0')
            return jsonify({"answer": f"Your largest holding is {top['name']} ({top['symbol']}), worth {fmt_money(Decimal(str(top['current_val'])))} ({pct}% of your portfolio)."})

        if 'percentage' in question or 'percent' in question or '%' in question or 'bitcoin' in question or 'btc' in question:
            for r in rows:
                if r['symbol'].lower() in question or r['name'].lower() in question:
                    pct = ((Decimal(str(r['current_val'])) / total_val) * Decimal('100')).quantize(Decimal('0.01')) if total_val > 0 else Decimal('0')
                    return jsonify({"answer": f"{r['name']} ({r['symbol']}) makes up {pct}% of your portfolio ({fmt_money(Decimal(str(r['current_val'])))})."})
            btc = next((r for r in rows if r['symbol'] == 'BTC'), None)
            if btc:
                pct = ((Decimal(str(btc['current_val'])) / total_val) * Decimal('100')).quantize(Decimal('0.01'))
                return jsonify({"answer": f"Bitcoin (BTC) represents {pct}% of your portfolio ({fmt_money(Decimal(str(btc['current_val'])))})."})
            return jsonify({"answer": "Bitcoin (BTC) is currently 0% of your portfolio."})

        return jsonify({
            "answer": f"Portfolio Summary: Value {fmt_money(total_val)} | Invested {fmt_money(total_inv)} | Unrealized P&L {fmt_money(unrealized)}. Ask about your best performer, largest holding, coin allocation %, or recent transactions."
        })
    finally:
        cursor.close()
        conn.close()


# --- PDF & CSV REPORT GENERATOR ---
@app.route('/api/reports/<report_type>/<fmt>', methods=['GET'])
@login_required
def export_report(user, report_type, fmt):
    uid = user['user_id']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        headers = []
        rows_data = []
        title = f"CryptoVault {report_type.title()} Report"

        if report_type in ('portfolio', 'allocation', 'pnl', 'performance'):
            cursor.execute("""
                SELECT h.symbol, c.name, h.quantity, h.avg_buy_price, h.total_invested, h.realized_pnl,
                       c.current_price, ROUND(h.quantity * c.current_price, 2) AS current_value,
                       ROUND((h.quantity * c.current_price) - h.total_invested, 2) AS unrealized_pnl
                FROM portfolio_holdings h
                JOIN cryptocurrencies c ON h.symbol = c.symbol
                WHERE h.user_id = %s AND h.quantity > 0
                ORDER BY current_value DESC
            """, (uid,))
            recs = cursor.fetchall()
            total_val = sum((Decimal(str(r['current_value'])) for r in recs), Decimal('0'))
            headers = ['Symbol', 'Name', 'Quantity', 'Avg Buy (USD)', 'Invested (USD)', 'Current Value (USD)', 'Unrealized P&L', 'Realized P&L', 'Allocation %']
            for r in recs:
                alloc = round(float((Decimal(str(r['current_value'])) / total_val) * 100), 2) if total_val > 0 else 0.0
                rows_data.append([
                    r['symbol'], r['name'], f"{float(r['quantity']):g}", f"{float(r['avg_buy_price']):.2f}",
                    f"{float(r['total_invested']):.2f}", f"{float(r['current_value']):.2f}",
                    f"{float(r['unrealized_pnl']):.2f}", f"{float(r['realized_pnl']):.2f}", f"{alloc}%"
                ])
        elif report_type == 'transactions':
            cursor.execute("""
                SELECT tx_id, DATE_FORMAT(tx_date, '%Y-%m-%d %H:%i') AS dt, tx_type, symbol,
                       quantity, price_per_coin, fee, COALESCE(notes, '') AS notes
                FROM transactions WHERE user_id = %s ORDER BY tx_date DESC
            """, (uid,))
            headers = ['Tx ID', 'Date', 'Type', 'Symbol', 'Quantity', 'Price (USD)', 'Fee (USD)', 'Notes']
            for r in cursor.fetchall():
                rows_data.append([
                    str(r['tx_id']), r['dt'], r['tx_type'], r['symbol'],
                    f"{float(r['quantity']):g}", f"{float(r['price_per_coin']):.2f}", f"{float(r['fee']):.2f}", r['notes']
                ])
        elif report_type == 'tax':
            cursor.execute("SELECT symbol, realized_pnl, total_invested FROM portfolio_holdings WHERE user_id = %s", (uid,))
            headers = ['Symbol', 'Invested (USD)', 'Realized Gain/Loss (USD)', 'Est. 30% VDA Tax (USD)', 'Note']
            for r in cursor.fetchall():
                rp = Decimal(str(r['realized_pnl'] or 0))
                tax = (max(Decimal('0'), rp) * Decimal('0.30')).quantize(Decimal('0.01'))
                rows_data.append([r['symbol'], f"{float(r['total_invested']):.2f}", f"{float(rp):.2f}", f"{float(tax):.2f}", 'Educational Estimate'])
        else:
            return jsonify({"error": "Invalid report type."}), 400

        log_audit(uid, 'REPORT_EXPORT', f"Exported {report_type} report as {fmt.upper()}")

        if fmt == 'csv':
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(headers)
            writer.writerows(rows_data)
            return Response(
                out.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment; filename=cryptovault_{report_type}.csv"}
            )

        if fmt == 'pdf':
            pdf = FPDF(orientation='L', unit='mm', format='A4')
            pdf.add_page()
            pdf.set_font('Helvetica', 'B', 15)
            pdf.cell(0, 10, f"{title} - {user['full_name']}", ln=True)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | User: {user['email']}", ln=True)
            if report_type == 'tax':
                pdf.cell(0, 6, "Disclaimer: Educational estimate only, not professional tax advice.", ln=True)
            pdf.ln(4)

            col_w = 275 / max(1, len(headers))
            pdf.set_font('Helvetica', 'B', 8)
            for h in headers:
                pdf.cell(col_w, 8, h[:18], border=1)
            pdf.ln()

            pdf.set_font('Helvetica', '', 8)
            for row in rows_data:
                for val in row:
                    safe_txt = val.encode('latin-1', 'replace').decode('latin-1')[:20]
                    pdf.cell(col_w, 7, safe_txt, border=1)
                pdf.ln()

            pdf_bytes = bytes(pdf.output())
            return Response(
                pdf_bytes,
                mimetype='application/pdf',
                headers={"Content-Disposition": f"attachment; filename=cryptovault_{report_type}.pdf"}
            )
        return jsonify({"error": "Format must be pdf or csv."}), 400
    finally:
        cursor.close()
        conn.close()


# --- SUPPORT CENTRE ---
@app.route('/api/support', methods=['GET'])
@login_required
def get_support_data(user):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        if user['role'] == 'ADMIN':
            cursor.execute("""
                SELECT t.*, u.full_name, u.email,
                       DATE_FORMAT(t.created_at, '%Y-%m-%d %H:%i') AS created_fmt
                FROM support_tickets t
                JOIN users u ON t.user_id = u.user_id
                ORDER BY t.ticket_id DESC
            """)
        else:
            cursor.execute("""
                SELECT t.*, DATE_FORMAT(t.created_at, '%Y-%m-%d %H:%i') AS created_fmt
                FROM support_tickets t
                WHERE t.user_id = %s
                ORDER BY t.ticket_id DESC
            """, (user['user_id'],))
        tickets = cursor.fetchall()

        for t in tickets:
            cursor.execute("""
                SELECT m.message_id, m.sender_role, m.body, u.full_name AS sender_name,
                       DATE_FORMAT(m.created_at, '%Y-%m-%d %H:%i') AS created_at
                FROM ticket_messages m
                JOIN users u ON m.sender_id = u.user_id
                WHERE m.ticket_id = %s
                ORDER BY m.message_id ASC
            """, (t['ticket_id'],))
            t['messages'] = cursor.fetchall()

        return jsonify({"faqs": FAQ_ITEMS, "tickets": tickets})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/support/tickets', methods=['POST'])
@login_required
def create_support_ticket(user):
    data = request.get_json(silent=True) or {}
    subject = str(data.get('subject', '')).strip()[:180]
    category = str(data.get('category', 'General')).strip()[:60]
    message = str(data.get('message', '')).strip()
    rating = data.get('rating')
    if len(subject) < 3 or len(message) < 5:
        return jsonify({"error": "Enter a subject and detailed message."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO support_tickets (user_id, subject, category, rating)
            VALUES (%s, %s, %s, %s)
        """, (user['user_id'], subject, category, int(rating) if rating else None))
        tid = cursor.lastrowid
        cursor.execute("""
            INSERT INTO ticket_messages (ticket_id, sender_id, sender_role, body)
            VALUES (%s, %s, %s, %s)
        """, (tid, user['user_id'], user['role'], message))
        conn.commit()
        log_audit(user['user_id'], 'TICKET_CREATED', f"Created support ticket #{tid}: {subject}")
        return jsonify({"message": f"Support ticket #{tid} created."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/support/tickets/<int:ticket_id>/reply', methods=['POST'])
@login_required
def reply_support_ticket(user, ticket_id):
    data = request.get_json(silent=True) or {}
    body = str(data.get('body', '')).strip()
    new_status = str(data.get('status', '')).upper()
    if not body:
        return jsonify({"error": "Reply message cannot be empty."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM support_tickets WHERE ticket_id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket or (user['role'] != 'ADMIN' and ticket['user_id'] != user['user_id']):
            return jsonify({"error": "Ticket not found or unauthorized."}), 404

        cursor.execute("""
            INSERT INTO ticket_messages (ticket_id, sender_id, sender_role, body)
            VALUES (%s, %s, %s, %s)
        """, (ticket_id, user['user_id'], user['role'], body))

        if user['role'] == 'ADMIN' and new_status in ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'):
            cursor.execute("UPDATE support_tickets SET status = %s WHERE ticket_id = %s", (new_status, ticket_id))
            create_notification(
                ticket['user_id'],
                'SUPPORT',
                f"Support Ticket #{ticket_id} Updated",
                f"Status: {new_status}. Admin replied to your ticket."
            )
        conn.commit()
        return jsonify({"message": "Reply added."})
    finally:
        cursor.close()
        conn.close()


# --- DATABASE EXPLORER & GUARDED SQL CONSOLE ---
@app.route('/api/db/schema', methods=['GET'])
@login_required
def get_db_schema(user):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
            ORDER BY TABLE_TYPE, TABLE_NAME
        """)
        tables = cursor.fetchall()

        cursor.execute("""
            SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            ORDER BY TABLE_NAME, ORDINAL_POSITION
        """)
        columns = cursor.fetchall()

        cursor.execute("""
            SELECT TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL
        """)
        foreign_keys = cursor.fetchall()

        cursor.execute("""
            SELECT TABLE_NAME, INDEX_NAME, COLUMN_NAME, NON_UNIQUE
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
            ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
        """)
        indexes = cursor.fetchall()

        cursor.execute("""
            SELECT ROUTINE_NAME, ROUTINE_TYPE
            FROM information_schema.ROUTINES
            WHERE ROUTINE_SCHEMA = DATABASE()
        """)
        routines = cursor.fetchall()

        return jsonify({
            "tables": tables,
            "columns": columns,
            "foreign_keys": foreign_keys,
            "indexes": indexes,
            "routines": routines
        })
    finally:
        cursor.close()
        conn.close()


@app.route('/api/db/query', methods=['POST'])
@login_required
def execute_sql_console(user):
    data = request.get_json(silent=True) or {}
    raw_sql = str(data.get('sql', '')).strip().rstrip(';').strip()
    confirmed = bool(data.get('confirmed', False))

    if not raw_sql or ';' in raw_sql:
        return jsonify({"error": "Execute one single SQL statement at a time."}), 400

    upper_sql = re.sub(r'\s+', ' ', raw_sql.upper())
    forbidden_sensitive = (
        'OTP_VERIFICATIONS',
        'USER_SESSIONS',
        'PASSWORD_HASH',
        'INFORMATION_SCHEMA',
        'MYSQL.',
        'PERFORMANCE_SCHEMA',
        'INTO OUTFILE',
        'LOAD_FILE'
    )
    if any(tok in upper_sql for tok in forbidden_sensitive):
        log_audit(user['user_id'], 'SQL_BLOCKED', f"Blocked sensitive SQL query: {raw_sql[:120]}")
        return jsonify({"error": "Access to credential, session, and system metadata schemas is strictly blocked."}), 403

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Regular users: strictly read-only SELECT scoped to their authenticated user_id
        if user['role'] != 'ADMIN':
            if not upper_sql.startswith('SELECT '):
                return jsonify({"error": "Regular users may only execute read-only SELECT queries."}), 403
            if any(k in upper_sql for k in ('USERS', 'AUDIT_LOGS', 'DB_BACKUPS', 'SUPPORT_TICKETS', 'TICKET_MESSAGES')):
                return jsonify({"error": "Regular users cannot query user, audit, or backup tables."}), 403

            uid = int(user['user_id'])
            scoped_sql = raw_sql
            for tbl in ('portfolio_holdings', 'transactions', 'watchlist', 'price_alerts', 'notifications', 'v_user_portfolio_summary'):
                scoped_sql = re.sub(
                    rf'\b{tbl}\b',
                    f"(SELECT * FROM {tbl} WHERE user_id = {uid}) AS {tbl}",
                    scoped_sql,
                    flags=re.IGNORECASE
                )
            cursor.execute(scoped_sql)
            rows = cursor.fetchmany(100)
            log_audit(uid, 'USER_SQL_SELECT', f"Executed read-only query: {raw_sql[:140]}")
            return jsonify({
                "rows": rows,
                "row_count": len(rows),
                "message": f"Returned {len(rows)} rows (scoped to your user account)."
            })

        # Admin SQL Console: SELECT + guarded INSERT / UPDATE / DELETE
        allowed_starts = ('SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ')
        if not upper_sql.startswith(allowed_starts):
            return jsonify({"error": "Only SELECT, INSERT, UPDATE, and DELETE statements are permitted in the SQL Console."}), 403

        if not upper_sql.startswith('SELECT '):
            if 'USERS' in upper_sql:
                return jsonify({"error": "Direct DML on users table is blocked; use Admin User Controls."}), 403
            if not confirmed:
                return jsonify({"require_confirm": True, "error": "Confirm write operation before executing INSERT/UPDATE/DELETE."}), 400
            conn.start_transaction()
            cursor.execute(raw_sql)
            affected = cursor.rowcount
            conn.commit()
            log_audit(user['user_id'], 'ADMIN_SQL_WRITE', f"Admin executed ({affected} rows): {raw_sql[:180]}")
            return jsonify({"rows": [], "row_count": affected, "message": f"Statement committed ({affected} rows affected)."})

        cursor.execute(raw_sql)
        rows = cursor.fetchmany(200)
        for r in rows:
            r.pop('password_hash', None)
        log_audit(user['user_id'], 'ADMIN_SQL_SELECT', f"Admin queried: {raw_sql[:180]}")
        return jsonify({"rows": rows, "row_count": len(rows), "message": f"Returned {len(rows)} rows."})
    except Exception as exc:
        conn.rollback()
        return jsonify({"error": str(exc)}), 400
    finally:
        cursor.close()
        conn.close()


# --- ADMIN DASHBOARD, RESTRICTED SUPPORT ACCESS & BACKUPS ---
@app.route('/api/admin/overview', methods=['GET'])
@admin_required
def admin_overview(admin):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM v_platform_overview")
        stats = cursor.fetchone()

        cursor.execute("""
            SELECT user_id, full_name, email, mobile_number, role, account_status, email_verified, is_demo,
                   DATE_FORMAT(created_at, '%Y-%m-%d') AS created_at,
                   DATE_FORMAT(last_login_at, '%Y-%m-%d %H:%i') AS last_login_at
            FROM users
            ORDER BY user_id DESC
        """)
        users = cursor.fetchall()

        cursor.execute("""
            SELECT l.log_id, l.actor_user_id, l.target_user_id, l.event_type, l.description, l.ip_address,
                   DATE_FORMAT(l.created_at, '%Y-%m-%d %H:%i:%s') AS created_at
            FROM audit_logs l
            ORDER BY l.log_id DESC LIMIT 60
        """)
        logs = cursor.fetchall()

        cursor.execute("""
            SELECT backup_id, file_name, file_size_bytes, backup_type,
                   DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
            FROM db_backups
            ORDER BY backup_id DESC LIMIT 20
        """)
        backups = cursor.fetchall()

        return jsonify({
            "stats": {
                "total_users": stats['total_users'],
                "active_users": stats['active_users'],
                "total_transactions": stats['total_transactions'],
                "total_aum_usd": float(stats['total_aum_usd'] or 0)
            },
            "users": users,
            "audit_logs": logs,
            "backups": backups
        })
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/users/<int:target_id>/status', methods=['PUT'])
@admin_required
def admin_update_user_status(admin, target_id):
    if target_id == admin['user_id']:
        return jsonify({"error": "Cannot modify your own admin account status."}), 400
    status = str((request.get_json(silent=True) or {}).get('status', '')).upper()
    if status not in ('ACTIVE', 'DEACTIVATED', 'SUSPENDED'):
        return jsonify({"error": "Invalid status."}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET account_status = %s WHERE user_id = %s", (status, target_id))
        if status != 'ACTIVE':
            cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE user_id = %s", (target_id,))
        conn.commit()
        log_audit(admin['user_id'], 'ADMIN_USER_STATUS', f"Set user #{target_id} status to {status}", target_user_id=target_id)
        return jsonify({"message": f"User #{target_id} status updated to {status}."})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/support-inspect/<int:target_id>', methods=['POST'])
@admin_required
def admin_restricted_support_inspect(admin, target_id):
    reason = str((request.get_json(silent=True) or {}).get('reason', '')).strip()
    if len(reason) < 10:
        return jsonify({"error": "A detailed support justification (min 10 characters) is mandatory before viewing user portfolio records."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id, full_name, email, account_status FROM users WHERE user_id = %s", (target_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"error": "Target user not found."}), 404

        log_audit(
            admin['user_id'],
            'RESTRICTED_SUPPORT_ACCESS',
            f"Inspected user #{target_id} portfolio. Reason: {reason}",
            target_user_id=target_id
        )
        create_notification(
            target_id,
            'SECURITY',
            'Support Portfolio Access Logged',
            f"An administrator inspected your portfolio for support reason: {reason}"
        )

        cursor.execute("""
            SELECT symbol, CAST(quantity AS DOUBLE) AS quantity, CAST(total_invested AS DOUBLE) AS total_invested
            FROM portfolio_holdings WHERE user_id = %s
        """, (target_id,))
        holdings = cursor.fetchall()

        cursor.execute("""
            SELECT tx_id, tx_type, symbol, CAST(quantity AS DOUBLE) AS quantity,
                   CAST(price_per_coin AS DOUBLE) AS price_usd, DATE_FORMAT(tx_date, '%Y-%m-%d %H:%i') AS tx_date
            FROM transactions WHERE user_id = %s ORDER BY tx_date DESC LIMIT 20
        """, (target_id,))
        txs = cursor.fetchall()

        return jsonify({"user": target, "holdings": holdings, "transactions": txs})
    finally:
        cursor.close()
        conn.close()


@app.route('/api/admin/backups/create', methods=['POST'])
@admin_required
def admin_create_backup(admin):
    meta = create_verified_backup('MANUAL', created_by=admin['user_id'])
    log_audit(admin['user_id'], 'DB_BACKUP_CREATED', f"Created manual backup {meta['file_name']}")
    return jsonify({"message": f"Backup created: {meta['file_name']}", "backup": meta})


@app.route('/api/admin/backups/restore', methods=['POST'])
@admin_required
def admin_restore_backup(admin):
    data = request.get_json(silent=True) or {}
    file_name = os.path.basename(str(data.get('file_name', '')))
    if not data.get('confirmed'):
        return jsonify({"error": "Explicit restoration confirmation is required."}), 400
    sql_path = os.path.join(BACKUP_DIR, file_name)
    res = restore_from_backup(sql_path, actor_user_id=admin['user_id'])
    log_audit(
        admin['user_id'],
        'DB_BACKUP_RESTORED',
        f"Restored database from {file_name} (pre-restore snapshot: {res['pre_restore_backup']})"
    )
    return jsonify({
        "message": f"Database restored from {file_name}. Pre-restore backup saved as {res['pre_restore_backup']}."
    })


ensure_admin_otp_enum()
run_automatic_daily_backup()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
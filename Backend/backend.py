"""
BodhSetu Backend API Service
Flask-based REST API with Supabase integration, JWT authentication,
and salted password hashing.

Configuration is loaded from the .env file located inside this Backend directory.
File: Backend/backend.py
"""

import os
import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests
import urllib3

# Optional CORS import
try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False

# ------------------------------------------------------------------------------
# 1. Environment Configuration Loader
# ------------------------------------------------------------------------------
# Explicitly locate and load .env from the Backend folder
BACKEND_DIR = Path(__file__).resolve().parent
ENV_FILE = BACKEND_DIR / ".env"

if ENV_FILE.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=ENV_FILE)
    except ImportError:
        # Built-in lightweight fallback parser if python-dotenv is not installed
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key not in os.environ:
                        os.environ[key] = val

def get_clean_env(key, default=""):
    """Reads environment variable and strips outer quotes or whitespace."""
    val = os.getenv(key, default)
    if val:
        val = str(val).strip().strip("'\"")
    return val

SUPABASE_URL = get_clean_env("SUPABASE_URL", "https://ipxqutjnwyilfbletkir.supabase.co").rstrip("/")
SUPABASE_KEY = get_clean_env("SUPABASE_KEY", "sb_publishable_F2RHMXsrlRD3OYjfHt-YfQ_0x6Sf9O8")
SUPABASE_USER_TABLE = get_clean_env("SUPABASE_USER_TABLE", get_clean_env("SUPABASE_TABLE", "user_database"))

JWT_SECRET_KEY = get_clean_env("JWT_SECRET_KEY", "bodhsetu_master_jwt_secret_key_2026")
JWT_EXPIRATION_HOURS = int(get_clean_env("JWT_EXPIRATION_HOURS", 24))

app = Flask(__name__)

# Enable CORS for cross-origin frontend requests
if HAS_CORS:
    CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def add_cors_headers(response):
    """Guarantees browser fetch compatibility from any port or local file."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, apikey"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

# ------------------------------------------------------------------------------
# 2. Resilient Database Client Helpers
# ------------------------------------------------------------------------------
import re

def detect_and_normalize_contact(contact_raw):
    """
    Detects whether input is an email or mobile phone number.
    Returns: (contact_type, canonical_contact, list_of_query_variants)
    - If email: returns ('email', 'user@example.com', ['user@example.com'])
    - If mobile: returns ('mobile', '9876543210', ['9876543210', '+919876543210', '919876543210', '09876543210'])
    """
    raw = str(contact_raw or "").strip()
    if not raw:
        return None, "", []

    # Check for email format
    if "@" in raw:
        clean_email = raw.lower()
        return "email", clean_email, [clean_email]

    # Check for mobile number format (extract all digits)
    digits_only = re.sub(r"\D", "", raw)
    if len(digits_only) >= 10:
        core_10 = digits_only[-10:]
        variants = [
            core_10,
            f"+91{core_10}",
            f"91{core_10}",
            f"0{core_10}"
        ]
        return "mobile", core_10, variants

    return "unknown", raw, [raw]

def get_supabase_headers():
    """Generates authentication headers required by Supabase PostgREST API."""
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

def make_supabase_request(method, url, **kwargs):
    """
    Executes an HTTP request to Supabase.
    Includes automatic fallback for Windows proxy/SSL inspection certificates.
    """
    kwargs.setdefault("headers", get_supabase_headers())
    kwargs.setdefault("timeout", 15)
    try:
        return requests.request(method, url, **kwargs)
    except requests.exceptions.SSLError:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return requests.request(method, url, verify=False, **kwargs)

def sanitize_user(user_dict):
    """Removes sensitive fields like password hash before returning user data."""
    if not isinstance(user_dict, dict):
        return user_dict
    sanitized = dict(user_dict)
    sanitized.pop("password", None)
    return sanitized

def generate_jwt_token(user):
    """Creates a signed JWT token containing user identity and expiration."""
    payload = {
        "user_ui": user.get("user_ui"),
        "contact": user.get("contact"),
        "full_name": user.get("full_name"),
        "state": user.get("state"),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.datetime.now(datetime.timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")

def token_required(f):
    """
    Decorator to protect routes requiring a valid JWT session.
    Extracts Bearer token from 'Authorization' header.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return jsonify({"status": "ok"}), 200

        auth_header = request.headers.get("Authorization", "")
        token = None

        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        elif "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({
                "success": False,
                "error": "Authentication token missing. Provide 'Authorization: Bearer <token>'."
            }), 401

        try:
            decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            current_user_claims = decoded
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Session token expired. Please log in again."}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "error": f"Invalid token: {str(e)}"}), 401

        return f(current_user_claims, *args, **kwargs)
    return decorated

# ------------------------------------------------------------------------------
# 3. Health Route
# ------------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "online",
        "service": "BodhSetu Backend API",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "supabase_url": SUPABASE_URL,
        "supabase_user_table": SUPABASE_USER_TABLE,
        "env_loaded_from": str(ENV_FILE) if ENV_FILE.exists() else "Defaults",
        "cors_enabled": True
    }), 200

# ------------------------------------------------------------------------------
# 4. Check User / Contact Verification API (Login vs Register Route Decider)
# ------------------------------------------------------------------------------
@app.route("/api/check-user", methods=["GET", "POST", "OPTIONS"])
@app.route("/check-user", methods=["GET", "POST", "OPTIONS"])
@app.route("/api/verify-contact", methods=["GET", "POST", "OPTIONS"])
def check_user_exists():
    """
    Checks if a citizen with the provided email or mobile number exists in the database.
    - Accurately detects whether the contact is an email or phone number.
    - Handles phone formatting (+91, leading 0, plain 10 digits).
    - If found: returns exists=True (navigate to login.html)
    - If not found: returns exists=False (navigate to register.html)
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    contact = ""
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        contact = (data.get("contact") or data.get("email") or data.get("mobile") or "").strip()
    else:
        contact = (request.args.get("contact") or request.args.get("email") or request.args.get("mobile") or "").strip()

    if not contact:
        return jsonify({
            "success": False,
            "error": "Contact (email address or 10-digit mobile number) is required."
        }), 400

    contact_type, canonical_contact, candidates = detect_and_normalize_contact(contact)
    if not contact_type or contact_type == "unknown":
        return jsonify({
            "success": False,
            "error": "Please enter a valid email address or 10-digit mobile number."
        }), 400

    # Build Supabase query matching candidates
    if len(candidates) == 1:
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?contact=eq.{candidates[0]}&select=user_ui,contact,full_name,is_active"
    else:
        conditions = ",".join([f"contact.eq.{c}" for c in candidates])
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?or=({conditions})&select=user_ui,contact,full_name,is_active"

    try:
        resp = make_supabase_request("GET", fetch_url)
    except Exception as e:
        return jsonify({"success": False, "error": f"Database connection error: {str(e)}"}), 502

    # Case-sensitive table name fallback
    if resp.status_code == 404:
        if len(candidates) == 1:
            alt_url = f"{SUPABASE_URL}/rest/v1/User_Database?contact=eq.{candidates[0]}&select=user_ui,contact,full_name,is_active"
        else:
            conditions = ",".join([f"contact.eq.{c}" for c in candidates])
            alt_url = f"{SUPABASE_URL}/rest/v1/User_Database?or=({conditions})&select=user_ui,contact,full_name,is_active"
        alt_resp = make_supabase_request("GET", alt_url)
        if alt_resp.status_code == 200:
            resp = alt_resp

    if resp.status_code != 200:
        return jsonify({
            "success": False,
            "error": f"Database query returned status {resp.status_code}: {resp.text}"
        }), 500

    records = resp.json()
    if records and len(records) > 0:
        existing_user = records[0]
        matched_contact = existing_user.get("contact") or canonical_contact
        return jsonify({
            "success": True,
            "exists": True,
            "contact_type": contact_type,
            "contact": matched_contact,
            "action": "login",
            "redirect_to": f"login.html?contact={matched_contact}",
            "message": f"Found existing citizen account for this {contact_type}. Proceeding to Sign In.",
            "user_preview": {
                "contact": matched_contact,
                "full_name": existing_user.get("full_name")
            }
        }), 200
    else:
        return jsonify({
            "success": True,
            "exists": False,
            "contact_type": contact_type,
            "contact": canonical_contact,
            "action": "register",
            "redirect_to": f"register.html?contact={canonical_contact}",
            "message": f"No account found for this {contact_type}. Proceeding to Registration."
        }), 200


# ------------------------------------------------------------------------------
# 4. User Registration API
# ------------------------------------------------------------------------------
@app.route("/api/register", methods=["POST", "OPTIONS"])
@app.route("/register", methods=["POST", "OPTIONS"])
def register_user():
    """
    Registers a new citizen in the Supabase user_database table.
    - Validates mandatory fields (full_name, contact, password, state)
    - Hashes password with PBKDF2:SHA256 salt
    - Puts the record in Supabase
    - Returns JWT token and sanitized user record (excluding password)
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "Request body must be valid JSON or form data."}), 400

    # Read fields (supporting both snake_case and camelCase from frontend)
    full_name = (data.get("full_name") or data.get("fullName") or "").strip()
    contact = (data.get("contact") or "").strip()
    plain_password = data.get("password") or ""
    state = (data.get("state") or "").strip()

    district = (data.get("district") or "").strip() or None
    residence_type = (data.get("residence_type") or data.get("residenceType") or "").strip() or None
    age_group = (data.get("age_group") or data.get("ageGroup") or "").strip() or None
    preferred_language = (data.get("preferred_language") or data.get("preferredLanguage") or "").strip() or None
    highest_education = (data.get("highest_education") or data.get("highestEducation") or "").strip() or None
    education_status = (data.get("education_status") or data.get("educationStatus") or "").strip() or None
    primary_occupation = (data.get("primary_occupation") or data.get("primaryOccupation") or "").strip() or None
    annual_income = (data.get("annual_income") or data.get("annualIncome") or "").strip() or None

    # Validations
    if not full_name:
        return jsonify({"success": False, "error": "Full name is required."}), 400
    if not contact:
        return jsonify({"success": False, "error": "Contact (email or mobile) is required."}), 400
    if not plain_password or len(plain_password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters long."}), 400
    if not state:
        return jsonify({"success": False, "error": "State is required."}), 400

    contact_type, canonical_contact, candidates = detect_and_normalize_contact(contact)
    if not contact_type or contact_type == "unknown":
        return jsonify({"success": False, "error": "Contact must be a valid email or 10-digit mobile number."}), 400

    # Step A: Check if contact is already registered (checking all phone/email variants)
    if len(candidates) == 1:
        check_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?contact=eq.{candidates[0]}&select=user_ui,contact"
    else:
        conditions = ",".join([f"contact.eq.{c}" for c in candidates])
        check_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?or=({conditions})&select=user_ui,contact"

    try:
        check_resp = make_supabase_request("GET", check_url)
        if check_resp.status_code == 200:
            existing_users = check_resp.json()
            if existing_users and len(existing_users) > 0:
                return jsonify({
                    "success": False,
                    "error": f"An account with this {contact_type} already exists. Please sign in."
                }), 409
    except Exception as e:
        return jsonify({"success": False, "error": f"Database connection error: {str(e)}"}), 502

    # Step B: Securely hash password
    password_hash = generate_password_hash(plain_password, method="pbkdf2:sha256")

    # Step C: Prepare record for User_Database
    new_user_payload = {
        "full_name": full_name,
        "contact": canonical_contact,
        "password": password_hash,
        "state": state,
        "district": district,
        "residence_type": residence_type,
        "age_group": age_group,
        "preferred_language": preferred_language,
        "highest_education": highest_education,
        "education_status": education_status,
        "primary_occupation": primary_occupation,
        "annual_income": annual_income,
        "is_active": True
    }

    # Step D: Insert into Supabase table
    insert_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}"
    try:
        insert_resp = make_supabase_request("POST", insert_url, json=new_user_payload)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to save user: {str(e)}"}), 502

    # Case-sensitivity fallback if table is created as User_Database in Postgres
    if insert_resp.status_code == 404:
        alt_url = f"{SUPABASE_URL}/rest/v1/User_Database"
        alt_resp = make_supabase_request("POST", alt_url, json=new_user_payload)
        if alt_resp.status_code in (200, 201):
            insert_resp = alt_resp

    if insert_resp.status_code not in (200, 201):
        err_msg = insert_resp.text
        try:
            err_msg = insert_resp.json().get("message", err_msg)
        except Exception:
            pass
        return jsonify({
            "success": False,
            "error": f"Supabase error ({insert_resp.status_code}): {err_msg}"
        }), insert_resp.status_code

    created_data = insert_resp.json()
    created_user = created_data[0] if isinstance(created_data, list) and len(created_data) > 0 else created_data
    if not isinstance(created_user, dict):
        created_user = new_user_payload

    # Step E: Issue JWT session token
    token = generate_jwt_token(created_user)

    return jsonify({
        "success": True,
        "message": "Registration successful.",
        "token": token,
        "token_type": "Bearer",
        "expires_in_hours": JWT_EXPIRATION_HOURS,
        "user": sanitize_user(created_user)
    }), 201

# ------------------------------------------------------------------------------
# 5. User Login API
# ------------------------------------------------------------------------------
@app.route("/api/login", methods=["POST", "OPTIONS"])
@app.route("/login", methods=["POST", "OPTIONS"])
def login_user():
    """
    Authenticates citizen by matching contact and password.
    - Fetches user record from Supabase
    - Verifies password against stored salted hash
    - Issues JWT token
    - Returns full user profile EXCLUDING password
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json(silent=True) or request.form.to_dict()
    if not data:
        return jsonify({"success": False, "error": "Request body must be valid JSON or form data."}), 400

    contact = (data.get("contact") or "").strip()
    password = data.get("password") or ""

    if not contact or not password:
        return jsonify({"success": False, "error": "Both contact and password are required."}), 400

    contact_type, canonical_contact, candidates = detect_and_normalize_contact(contact)

    # Step A: Fetch user record from Supabase across matching candidates
    if len(candidates) == 1:
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?contact=eq.{candidates[0]}&select=*"
    else:
        conditions = ",".join([f"contact.eq.{c}" for c in candidates])
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?or=({conditions})&select=*"

    try:
        resp = make_supabase_request("GET", fetch_url)
    except Exception as e:
        return jsonify({"success": False, "error": f"Database query failed: {str(e)}"}), 502

    if resp.status_code == 404:
        alt_url = f"{SUPABASE_URL}/rest/v1/User_Database?contact=eq.{contact}&select=*"
        alt_resp = make_supabase_request("GET", alt_url)
        if alt_resp.status_code == 200:
            resp = alt_resp

    if resp.status_code != 200:
        return jsonify({
            "success": False,
            "error": f"Database query returned code {resp.status_code}: {resp.text}"
        }), 500

    records = resp.json()
    if not records or len(records) == 0:
        return jsonify({
            "success": False,
            "error": "Invalid contact or password."
        }), 401

    user_record = records[0]

    if user_record.get("is_active") is False:
        return jsonify({
            "success": False,
            "error": "This account is currently inactive."
        }), 403

    # Step B: Password Verification
    stored_password = user_record.get("password") or ""
    password_valid = False

    try:
        import hashlib
        client_sha256 = "sha256:" + hashlib.sha256(password.encode("utf-8")).hexdigest()

        if stored_password.startswith(("pbkdf2:", "scrypt:", "bcrypt$", "$2b$", "$2a$")):
            password_valid = check_password_hash(stored_password, password)
        elif stored_password == client_sha256 or stored_password == password:
            password_valid = True
            # Upgrade to secure Werkzeug PBKDF2 hash in background
            new_hash = generate_password_hash(password, method="pbkdf2:sha256")
            user_ui = user_record.get("user_ui")
            if user_ui:
                make_supabase_request(
                    "PATCH",
                    f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?user_ui=eq.{user_ui}",
                    json={"password": new_hash}
                )
    except Exception as e:
        app.logger.error(f"Password check exception: {e}")
        password_valid = (stored_password == password)

    if not password_valid:
        return jsonify({
            "success": False,
            "error": "Invalid contact or password."
        }), 401

    # Step C: Generate JWT Session Token
    token = generate_jwt_token(user_record)

    # Step D: Return sanitized profile (excludes password)
    safe_profile = sanitize_user(user_record)

    return jsonify({
        "success": True,
        "message": f"Welcome back, {safe_profile.get('full_name', 'Citizen')}!",
        "token": token,
        "token_type": "Bearer",
        "expires_in_hours": JWT_EXPIRATION_HOURS,
        "user": safe_profile
    }), 200

# ------------------------------------------------------------------------------
# 6. Authenticated Profile & Customization Session API
# ------------------------------------------------------------------------------
@app.route("/api/me", methods=["GET", "OPTIONS"])
@app.route("/api/profile", methods=["GET", "OPTIONS"])
@token_required
def get_user_profile(current_user):
    """Returns fresh citizen profile using JWT token (excludes password)."""
    user_ui = current_user.get("user_ui")
    contact = current_user.get("contact")

    if user_ui:
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?user_ui=eq.{user_ui}&select=*"
    else:
        fetch_url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?contact=eq.{contact}&select=*"

    try:
        resp = make_supabase_request("GET", fetch_url)
    except Exception as e:
        return jsonify({"success": False, "error": f"Database query failed: {str(e)}"}), 502

    if resp.status_code == 200 and resp.json():
        return jsonify({
            "success": True,
            "user": sanitize_user(resp.json()[0])
        }), 200

    return jsonify({"success": False, "error": "User profile not found."}), 404

@app.route("/api/profile", methods=["PUT", "OPTIONS"])
@token_required
def update_user_profile(current_user):
    """Updates profile demographic fields for scheme customization."""
    user_ui = current_user.get("user_ui")
    if not user_ui:
        return jsonify({"success": False, "error": "Invalid user identity in token."}), 400

    data = request.get_json(silent=True) or {}
    allowed_keys = [
        "full_name", "state", "district", "residence_type",
        "age_group", "preferred_language", "highest_education",
        "education_status", "primary_occupation", "annual_income"
    ]

    update_payload = {}
    for key in allowed_keys:
        camel = "".join([w.title() if i > 0 else w for i, w in enumerate(key.split("_"))])
        val = data.get(key, data.get(camel))
        if val is not None:
            update_payload[key] = val

    if not update_payload:
        return jsonify({"success": False, "error": "No valid profile fields provided to update."}), 400

    update_payload["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        resp = make_supabase_request(
            "PATCH",
            f"{SUPABASE_URL}/rest/v1/{SUPABASE_USER_TABLE}?user_ui=eq.{user_ui}",
            json=update_payload
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to update profile: {str(e)}"}), 502

    if resp.status_code in (200, 204):
        updated_records = resp.json() if resp.text else [update_payload]
        updated_user = updated_records[0] if isinstance(updated_records, list) and updated_records else updated_records
        return jsonify({
            "success": True,
            "message": "Profile updated successfully.",
            "user": sanitize_user(updated_user)
        }), 200

    return jsonify({"success": False, "error": f"Supabase update failed: {resp.text}"}), resp.status_code

# ------------------------------------------------------------------------------
# 7. Server Entry Point
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(get_clean_env("FLASK_PORT", 5000))
    debug_mode = get_clean_env("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")

    print("\n" + "="*60)
    print("  BODHSETU AUTH & PROFILE FLASK BACKEND")
    print("="*60)
    print(f"  • Running on:        http://127.0.0.1:{port}")
    print(f"  • Config Source:     {ENV_FILE}")
    print(f"  • Supabase URL:      {SUPABASE_URL}")
    print(f"  • User Table:        {SUPABASE_USER_TABLE}")
    print(f"  • JWT Expiration:    {JWT_EXPIRATION_HOURS} hours")
    print(f"  • CORS:              Enabled")
    print("="*60 + "\n")

    app.run(host="0.0.0.0", port=port, debug=debug_mode)

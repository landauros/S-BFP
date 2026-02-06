import csv
import os
import secrets
import string
import threading
import time
import webbrowser
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from Webgl.routes import webgl_bp
from Audio.routes import audio_bp
from Canvas.routes import canvas_bp
from User_Manager.user_manager import (
    register_user,
    authenticate_user,
    store_user_fingerprint,
    append_triangle_stability,
    get_user_record,
    set_triangle_baseline,
    append_audio_stability,
    set_audio_baseline,
    append_canvas_stability,
    set_canvas_baseline,
)
fix_hash = 0
current_user = None  # currently active username
auth_status = True
total_auth = True
global_hashes = []
device_info = {}
request_count = 0      # ✅ counter: track /analyze calls
SAVE_INTERVAL = 10     # ✅ persist CSV every 10 requests
app = Flask(__name__)
# Register blueprints
app.register_blueprint(webgl_bp, url_prefix='/webgl')
app.register_blueprint(audio_bp, url_prefix='/audio')
app.register_blueprint(canvas_bp, url_prefix='/canvas')

SESSION_TIMEOUT_SECONDS = 300
_session_state = {
    "owner": None,
    "token": None,
    "acquired_at": None,
    "last_heartbeat": None,
}
_session_lock = threading.Lock()


def _clear_session_locked():
    """Reset the exclusive session state (call under _session_lock)."""
    _session_state["owner"] = None
    _session_state["token"] = None
    _session_state["acquired_at"] = None
    _session_state["last_heartbeat"] = None


def _is_session_stale(now_ts):
    """Determine if the active session exceeded the timeout."""
    last = _session_state["last_heartbeat"]
    if _session_state["owner"] is None or last is None:
        return False
    return (now_ts - last) > SESSION_TIMEOUT_SECONDS


def _expire_session_if_needed(now_ts=None):
    """Release the session if it timed out."""
    now_ts = now_ts or time.time()
    if _is_session_stale(now_ts):
        _clear_session_locked()


def _validate_session_owner(username: str):
    """Ensure the requesting user matches the active exclusive session."""
    username = (username or "").strip()
    with _session_lock:
        _expire_session_if_needed()
        owner = _session_state["owner"]
        if not owner:
            return False, "The testing system is currently idle."
        if owner.lower() != username.lower():
            return (
                False,
                "Another user is currently running tests. Please try again later.",
            )
    return True, None


def generate_secure_password(length: int = 16) -> str:
    """Generate a random password with mixed character classes."""
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{}"
    specials = set("!@#$%^&*()-_=+[]{}")
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in specials for c in password)
        ):
            return password

def open_browser():
    time.sleep(1.5)
    webbrowser.open_new('http://127.0.0.1:5001/')
@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or "").strip()
    generated_password = generate_secure_password()
    ok, msg = register_user(username, generated_password, auto_generated=True)
    if ok:
        return jsonify(status='ok', username=msg, password=generated_password)
    else:
        return jsonify(status='error', error=msg)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or "").strip()
    password = (data.get('password') or "").strip()
    ok, msg = authenticate_user(username,password)
    if ok:
        return jsonify(status='ok', username=msg)
    else:
        return jsonify(status='error', error=msg)


@app.route('/session/acquire', methods=['POST'])
def acquire_session():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify(status='error', error="Username is required"), 400

    now_ts = time.time()
    with _session_lock:
        _expire_session_if_needed(now_ts)
        owner = _session_state["owner"]
        if owner and owner.lower() != username.lower():
            acquired_at = _session_state["acquired_at"]
            started_at = (
                datetime.fromtimestamp(acquired_at).isoformat()
                if acquired_at
                else None
            )
            return (
                jsonify(
                    status="busy",
                    owner=owner,
                    startedAt=started_at,
                    timeout=SESSION_TIMEOUT_SECONDS,
                ),
                409,
            )

        if owner and owner.lower() == username.lower():
            _session_state["last_heartbeat"] = now_ts
            return jsonify(
                status="ok",
                token=_session_state["token"],
                timeout=SESSION_TIMEOUT_SECONDS,
            )

        token = secrets.token_hex(32)
        _session_state["owner"] = username
        _session_state["token"] = token
        _session_state["acquired_at"] = now_ts
        _session_state["last_heartbeat"] = now_ts
        return jsonify(status="ok", token=token, timeout=SESSION_TIMEOUT_SECONDS)


@app.route('/session/heartbeat', methods=['POST'])
def heartbeat_session():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    token = (data.get("token") or "").strip()
    if not username or not token:
        return jsonify(status='error', error="Username and token are required"), 400

    now_ts = time.time()
    with _session_lock:
        _expire_session_if_needed(now_ts)
        owner = _session_state["owner"]
        if (
            owner
            and owner.lower() == username.lower()
            and _session_state["token"] == token
        ):
            _session_state["last_heartbeat"] = now_ts
            return jsonify(status="ok")

    return jsonify(status='error', error="Session is no longer active"), 409


@app.route('/session/release', methods=['POST'])
def release_session():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    token = (data.get("token") or "").strip()
    if not username or not token:
        return jsonify(status='error', error="Username and token are required"), 400

    with _session_lock:
        owner = _session_state["owner"]
        if (
            owner
            and owner.lower() == username.lower()
            and _session_state["token"] == token
        ):
            _clear_session_locked()
            return jsonify(status="ok")

    return jsonify(status='error', error="Session release rejected"), 409


@app.route('/user/fingerprint', methods=['POST'])
def capture_fingerprint():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    ok_session, session_msg = _validate_session_owner(username)
    if not ok_session:
        return jsonify(status='error', error=session_msg), 409
    fingerprint_details = data.get("fingerprint")
    captured_at = data.get("timestamp") or time.strftime('%Y-%m-%d %H:%M:%S')

    payload = {
        "captured_at": captured_at,
        "hash": data.get("fingerprintHash"),
        "fingerprint_string": data.get("fingerprintString"),
        "details": fingerprint_details,
        "client_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }

    ok, msg = store_user_fingerprint(username, payload)
    if ok:
        return jsonify(status="ok")
    return jsonify(status='error', error=msg), 400


@app.route('/user/triangle_stability', methods=['POST'])
def record_triangle_stability():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify(status='error', error="Username is required"), 400
    ok_session, session_msg = _validate_session_owner(username)
    if not ok_session:
        return jsonify(status='error', error=session_msg), 409

    user_record = get_user_record(username)
    if user_record is None:
        return jsonify(status='error', error="User does not exist"), 404

    runs_payload = data.get("testRuns") or []
    hashes = [run.get("hash") for run in runs_payload if isinstance(run, dict) and run.get("hash")]
    if not hashes:
        return jsonify(status='error', error="Missing valid hash data"), 400

    # Determine baseline: prefer existing user baseline; otherwise use client provided baseline or first hash
    stored_baseline = (user_record.get("triangle_baseline") or "").strip()
    client_baseline = (data.get("baselineHash") or data.get("localBaseline") or "").strip()
    baseline_used = stored_baseline or client_baseline or hashes[0]

    if not stored_baseline:
        set_triangle_baseline(username, baseline_used)

    mismatches = [idx + 1 for idx, hash_value in enumerate(hashes) if hash_value != baseline_used]
    all_stable = len(mismatches) == 0

    record = {
        "captured_at": data.get("timestamp") or time.strftime('%Y-%m-%d %H:%M:%S'),
        "seed": data.get("seed"),
        "baseline_hash": baseline_used,
        "all_stable": all_stable,
        "unique_hashes": list(dict.fromkeys(hashes)),  # preserve order
        "runs": runs_payload,
        "hashes": hashes,
        "mismatch_runs": mismatches,
        "client_ip": request.remote_addr,
    }

    ok, msg = append_triangle_stability(username, record)
    if ok:
        alert_message = (
            f"Rendering stable: all {len(hashes)} hashes matched the baseline {baseline_used}."
            if all_stable
            else f"Inconsistencies detected: runs {', '.join(map(str, mismatches))} deviated from baseline {baseline_used}."
        )
        response = {
            "status": "ok",
            "baselineHash": baseline_used,
            "allStable": all_stable,
            "mismatchRuns": mismatches,
            "totalRuns": len(hashes),
            "alertMessage": alert_message,
        }
        return jsonify(response)
    return jsonify(status='error', error=msg), 400




@app.route('/user/audio_stability', methods=['POST'])
def record_audio_stability():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify(status='error', error="Username is required"), 400
    ok_session, session_msg = _validate_session_owner(username)
    if not ok_session:
        return jsonify(status='error', error=session_msg), 409

    user_record = get_user_record(username)
    if user_record is None:
        return jsonify(status='error', error="User does not exist"), 404

    runs_payload = data.get("testRuns") or []
    hashes = [
        run.get("waveformHash")
        for run in runs_payload
        if isinstance(run, dict) and run.get("waveformHash")
    ]
    if not hashes:
        return jsonify(status='error', error="Missing valid hash data"), 400

    stored_baseline = (user_record.get("audio_baseline") or "").strip()
    client_baseline = (
        data.get("baselineHash")
        or data.get("localBaseline")
        or ""
    ).strip()
    baseline_used = stored_baseline or client_baseline or hashes[0]

    if not stored_baseline:
        set_audio_baseline(username, baseline_used)

    mismatches = [
        idx + 1
        for idx, hash_value in enumerate(hashes)
        if hash_value != baseline_used
    ]
    all_stable = len(mismatches) == 0

    record = {
        "captured_at": data.get("timestamp") or time.strftime('%Y-%m-%d %H:%M:%S'),
        "session_id": data.get("sessionId"),
        "baseline_hash": baseline_used,
        "all_stable": all_stable,
        "unique_hashes": list(dict.fromkeys(hashes)),
        "runs": runs_payload,
        "hashes": hashes,
        "mismatch_runs": mismatches,
        "stability_rate": data.get("stabilityRate"),
        "total_runs": len(hashes),
        "client_ip": request.remote_addr,
    }

    ok, msg = append_audio_stability(username, record)
    if ok:
        alert_message = (
            f"Audio hashes stable: all {len(hashes)} hashes matched the baseline {baseline_used}."
            if all_stable
            else f"Audio test detected inconsistencies: runs {', '.join(map(str, mismatches))} deviated from baseline {baseline_used}."
        )
        response = {
            "status": "ok",
            "baselineHash": baseline_used,
            "allStable": all_stable,
            "mismatchRuns": mismatches,
            "totalRuns": len(hashes),
            "alertMessage": alert_message,
        }
        return jsonify(response)
    return jsonify(status='error', error=msg), 400


@app.route('/user/canvas_stability', methods=['POST'])
def record_canvas_stability():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify(status='error', error="Username is required"), 400
    ok_session, session_msg = _validate_session_owner(username)
    if not ok_session:
        return jsonify(status='error', error=session_msg), 409

    user_record = get_user_record(username)
    if user_record is None:
        return jsonify(status='error', error="User does not exist"), 404

    seed = (data.get("seed") or "").strip()
    runs_payload = data.get("testRuns") or []
    hashes = [
        run.get("hash")
        for run in runs_payload
        if isinstance(run, dict) and run.get("hash")
    ]
    if not hashes:
        return jsonify(status='error', error="Missing valid hash data"), 400

    raw_baseline = user_record.get("canvas_baseline")
    if isinstance(raw_baseline, dict):
        stored_baseline = (raw_baseline.get(seed) or raw_baseline.get("__default__") or "").strip()
    else:
        stored_baseline = (raw_baseline or "").strip()
    client_baseline = (
        data.get("baselineHash")
        or data.get("localBaseline")
        or ""
    ).strip()
    baseline_used = stored_baseline or client_baseline or hashes[0]

    if not stored_baseline:
        set_canvas_baseline(username, seed, baseline_used)

    mismatches = [
        idx + 1
        for idx, hash_value in enumerate(hashes)
        if hash_value != baseline_used
    ]
    all_stable = len(mismatches) == 0

    record = {
        "captured_at": data.get("timestamp") or time.strftime('%Y-%m-%d %H:%M:%S'),
        "seed": data.get("seed"),
        "baseline_hash": baseline_used,
        "all_stable": all_stable,
        "unique_hashes": list(dict.fromkeys(hashes)),
        "runs": runs_payload,
        "hashes": hashes,
        "mismatch_runs": mismatches,
        "client_ip": request.remote_addr,
    }

    config_meta = data.get("drawConfig")
    if config_meta is not None:
        record["draw_config"] = config_meta

    ok, msg = append_canvas_stability(username, record)
    if ok:
        alert_message = (
            f"Canvas rendering stable: all {len(hashes)} hashes matched the baseline {baseline_used}."
            if all_stable
            else f"Canvas test detected inconsistencies: runs {', '.join(map(str, mismatches))} deviated from baseline {baseline_used}."
        )
        response = {
            "status": "ok",
            "baselineHash": baseline_used,
            "allStable": all_stable,
            "mismatchRuns": mismatches,
            "totalRuns": len(hashes),
            "alertMessage": alert_message,
        }
        return jsonify(response)
    return jsonify(status='error', error=msg), 400


if __name__ == '__main__':


    threading.Thread(target=open_browser).start()

    app.run(debug=True, port=5001,use_reloader=False)

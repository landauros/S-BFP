import os, json, threading, tempfile, time
from werkzeug.security import generate_password_hash, check_password_hash
from copy import deepcopy

# Data paths
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
USERS_DIR = os.path.join(DATA_DIR, 'users')
os.makedirs(USERS_DIR, exist_ok=True)
LEGACY_USERS_FILE = os.path.join(DATA_DIR, 'users.json')

# Concurrency locks
_users_lock = threading.Lock()
_init_lock = threading.Lock()
_storage_initialized = False


# ---------------------------
# Basic file operations
# ---------------------------

def _ensure_storage_initialized():
    """Migrate legacy aggregated storage to per-user files once."""
    global _storage_initialized
    if _storage_initialized:
        return
    with _init_lock:
        if _storage_initialized:
            return
        if os.path.exists(LEGACY_USERS_FILE):
            try:
                with open(LEGACY_USERS_FILE, 'r', encoding='utf-8') as f:
                    legacy_data = json.load(f)
                if isinstance(legacy_data, list):
                    for entry in legacy_data:
                        if isinstance(entry, dict) and entry.get("username"):
                            username = entry["username"]
                            path = os.path.join(USERS_DIR, f"{username}.json")
                            _write_user_atomic(path, entry)
            except Exception:
                pass  # best effort migration
            try:
                os.remove(LEGACY_USERS_FILE)
            except OSError:
                pass
        _storage_initialized = True


def _write_user_atomic(path, user_data):
    """Atomically write a single user file."""
    fd, tmp_path = tempfile.mkstemp(dir=USERS_DIR, prefix='user_', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(user_data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _load_user_file(path):
    """Load a single user file and ensure a dict response."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _list_user_entries():
    try:
        return [name for name in os.listdir(USERS_DIR) if name.endswith(".json")]
    except FileNotFoundError:
        return []


def _resolve_username_path(username):
    """Find the file path and canonical username for the given username."""
    target = (username or "").strip()
    if not target:
        return None, None
    candidate = os.path.join(USERS_DIR, f"{target}.json")
    if os.path.exists(candidate):
        return candidate, target
    lower = target.lower()
    for entry in _list_user_entries():
        base = entry[:-5]
        if base.lower() == lower:
            return os.path.join(USERS_DIR, entry), base
    return None, None


def _update_user_record(username, mutator):
    """Internal helper to mutate a specific user and persist the change."""
    _ensure_storage_initialized()
    with _users_lock:
        path, canonical = _resolve_username_path(username)
        if not path:
            return False, "User not found"
        user = _load_user_file(path) or {}
        if not user.get("username"):
            user["username"] = canonical
        try:
            mutator(user)
        except Exception as exc:  # noqa: BLE001
            return False, f"Failed to update user data: {exc}"
        try:
            _write_user_atomic(path, user)
        except Exception:
            return False, "Server write failed"
        return True, "ok"


# ---------------------------
# User operations
# ---------------------------

def register_user(username, password, *, auto_generated=False):
    """
    Register a user and return (True, username) or (False, error_message).
    If auto_generated is True, the supplied password is assumed to already satisfy
    the desired complexity requirements.
    """
    _ensure_storage_initialized()
    username = username.strip()
    password = (password or "").strip()
    if not username:
        return False, "Username is required"
    if not (3 <= len(username) <= 20) or not all(c.isalnum() or c == '_' for c in username):
        return False, "Invalid username format (letters, digits, underscores; length 3-20)"
    if not password:
        return False, "Password must be provided"
    if not auto_generated and len(password) < 6:
        return False, "Password must be at least 6 characters long"

    with _users_lock:
        path, _ = _resolve_username_path(username)
        if path:
            return False, "Username already exists"

        pwd_hash = generate_password_hash(password)
        user_payload = {
            "username": username,
            "password_hash": pwd_hash,
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        target_path = os.path.join(USERS_DIR, f"{username}.json")
        try:
            _write_user_atomic(target_path, user_payload)
        except Exception:
            return False, "Server write failed"

    return True, username


def authenticate_user(username, password):
    """
    Validate login credentials and return (True, username) or (False, error_message).
    """
    _ensure_storage_initialized()
    username = username.strip()
    if not username or not password:
        return False, "Username or password cannot be empty"

    with _users_lock:
        path, canonical = _resolve_username_path(username)
        if not path:
            return False, "User not found"
        user = _load_user_file(path)
        if not user:
            return False, "User not found"
        pwd_hash = user.get("password_hash")
        if not pwd_hash or not check_password_hash(pwd_hash, password):
            return False, "Incorrect password"
        return True, user.get("username", canonical)


def list_users():
    """Debug helper: return a list of usernames."""
    _ensure_storage_initialized()
    with _users_lock:
        usernames = []
        for entry in _list_user_entries():
            path = os.path.join(USERS_DIR, entry)
            data = _load_user_file(path)
            usernames.append(data.get("username") or entry[:-5])
        return usernames


def get_user_record(username):
    """Get the full user record (deep copy to avoid external mutation)."""
    _ensure_storage_initialized()
    username = (username or "").strip()
    if not username:
        return None
    with _users_lock:
        path, _ = _resolve_username_path(username)
        if not path:
            return None
        record = _load_user_file(path)
        if not record:
            return None
        return deepcopy(record)
    return None


def store_user_fingerprint(username, fingerprint_payload):
    """
    Save the user's static fingerprint information.
    """
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(fingerprint_payload, dict):
        return False, "Invalid fingerprint data format"

    return _update_user_record(
        username,
        lambda user: user.__setitem__("fingerprint", fingerprint_payload),
    )


def store_system_timing(username, timing_record):
    """
    Save the total system timing (from fingerprint capture start to all tests complete).
    """
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(timing_record, dict):
        return False, "Invalid timing data format"

    return _update_user_record(
        username,
        lambda user: user.__setitem__("system_timing", timing_record),
    )


def append_triangle_stability(username, stability_record):
    """
    Record WebGL triangle stability results.
    """
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(stability_record, dict):
        return False, "Invalid result data format"

    def mutator(user):
        history = user.setdefault("triangle_stability", [])
        history.append(stability_record)

    return _update_user_record(username, mutator)


def set_triangle_baseline(username, baseline_hash, *, overwrite=False):
    """
    Set or update the user's triangle baseline hash.
    """
    username = (username or "").strip()
    baseline_hash = (baseline_hash or "").strip()
    if not username:
        return False, "Username is required"
    if not baseline_hash:
        return False, "Baseline hash is required"

    def mutator(user):
        if overwrite or not user.get("triangle_baseline"):
            user["triangle_baseline"] = baseline_hash

    return _update_user_record(username, mutator)


def append_triangle2_stability(username, stability_record):
    """Record WebGL (routes2) triangle stability results."""
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(stability_record, dict):
        return False, "Invalid result data format"

    def mutator(user):
        history = user.setdefault("triangle2_stability", [])
        history.append(stability_record)

    return _update_user_record(username, mutator)


def set_triangle2_baseline(username, baseline_hash, *, overwrite=False):
    """Set or update the routes2 WebGL triangle baseline hash."""
    username = (username or "").strip()
    baseline_hash = (baseline_hash or "").strip()
    if not username:
        return False, "Username is required"
    if not baseline_hash:
        return False, "Baseline hash is required"

    def mutator(user):
        if overwrite or not user.get("triangle2_baseline"):
            user["triangle2_baseline"] = baseline_hash

    return _update_user_record(username, mutator)


def append_audio_stability(username, stability_record):
    """Record audio automated test stability results."""
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(stability_record, dict):
        return False, "Invalid result data format"

    def mutator(user):
        history = user.setdefault("audio_stability", [])
        history.append(stability_record)

    return _update_user_record(username, mutator)


def set_audio_baseline(username, baseline_hash, *, overwrite=False):
    """Set or update the user's audio baseline hash."""
    username = (username or "").strip()
    baseline_hash = (baseline_hash or "").strip()
    if not username:
        return False, "Username is required"
    if not baseline_hash:
        return False, "Baseline hash is required"

    def mutator(user):
        if overwrite or not user.get("audio_baseline"):
            user["audio_baseline"] = baseline_hash

    return _update_user_record(username, mutator)


def append_canvas_stability(username, stability_record):
    """Record Canvas automated test stability results."""
    username = (username or "").strip()
    if not username:
        return False, "Username is required"
    if not isinstance(stability_record, dict):
        return False, "Invalid result data format"

    def mutator(user):
        history = user.setdefault("canvas_stability", [])
        history.append(stability_record)

    return _update_user_record(username, mutator)


def set_canvas_baseline(username, seed, baseline_hash, *, overwrite=False):
    """Set or update the user's Canvas baseline hash (segmented by seed)."""
    username = (username or "").strip()
    seed = (seed or "__default__").strip() or "__default__"
    baseline_hash = (baseline_hash or "").strip()
    if not username:
        return False, "Username is required"
    if not baseline_hash:
        return False, "Baseline hash is required"

    def mutator(user):
        baselines = user.get("canvas_baseline")
        if isinstance(baselines, dict):
            target = baselines
        elif baselines:
            # Legacy format was a string; migrate to the default slot.
            target = {"__default__": baselines}
        else:
            target = {}

        if overwrite or target.get(seed) in (None, ""):
            target[seed] = baseline_hash

        user["canvas_baseline"] = target

    return _update_user_record(username, mutator)

"""Central configuration for the S-BFP research artifact.

Defaults are deterministic so evaluators can run the artifact without provisioning
secrets. Deployments must override both secret environment variables.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


_DEMO_SERVER_SECRET = "s-bfp-artifact-demo-secret-not-for-production"
_DEMO_SESSION_SECRET = "s-bfp-artifact-session-secret-not-for-production"


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SERVER_SECRET = os.getenv("S_BFP_SERVER_SECRET", _DEMO_SERVER_SECRET).encode("utf-8")
FLASK_SESSION_SECRET = os.getenv("S_BFP_SESSION_SECRET", _DEMO_SESSION_SECRET)

HOST = os.getenv("S_BFP_HOST", "127.0.0.1")
PORT = int(os.getenv("S_BFP_PORT", "5001"))
DEBUG = env_bool("S_BFP_DEBUG", False)
OPEN_BROWSER = env_bool("S_BFP_OPEN_BROWSER", True)

STORE_CLIENT_METADATA = env_bool("S_BFP_STORE_CLIENT_METADATA", False)
STORE_RAW_FINGERPRINT = env_bool("S_BFP_STORE_RAW_FINGERPRINT", False)
MAX_CONTENT_LENGTH = int(os.getenv("S_BFP_MAX_UPLOAD_MIB", "12")) * 1024 * 1024

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "User_Manager" / "data"
DATA_DIR = Path(os.getenv("S_BFP_DATA_DIR", str(DEFAULT_DATA_DIR))).resolve()


def derive_secret(label: str) -> bytes:
    """Derive a modality-specific 256-bit secret from the server secret."""

    return hmac.new(SERVER_SECRET, label.encode("utf-8"), hashlib.sha256).digest()


USING_DEMO_SERVER_SECRET = SERVER_SECRET == _DEMO_SERVER_SECRET.encode("utf-8")
USING_DEMO_SESSION_SECRET = FLASK_SESSION_SECRET == _DEMO_SESSION_SECRET


"""Lightweight audio test routes."""

from __future__ import annotations

import struct
from datetime import datetime

import flask
from flask import Blueprint, jsonify

from drbg import HMACDRBG

audio_bp = Blueprint(
    "audio",
    __name__,
    template_folder="templates",
    static_folder="static",
)

_ENTROPY = b"asdfasdgsadg"


def _build_drbg(seed: str, salt: bytes) -> HMACDRBG:
    seed_bytes = seed.encode("utf-8")
    return HMACDRBG(
        entropy_input=_ENTROPY,
        nonce=salt,
        personalization_string=seed_bytes,
    )


@audio_bp.route("/")
def index() -> flask.Response:
    """Serve the streamlined audio stability UI."""
    return flask.send_file("Audio/index.html")


@audio_bp.route(
    "/get_snippets_config/"
    "<string:seed>/<int:duration>/<int:sample_rate>/<int:n>"
    "/<int:min_length>/<int:max_length>/<int:min_frequency>/<int:max_frequency>"
)
def get_snippets_config(
    seed: str,
    duration: int,
    sample_rate: int,
    n: int,
    min_length: int,
    max_length: int,
    min_frequency: int,
    max_frequency: int,
):
    """Return deterministic snippet gaps/frequencies for the requested seed."""

    n = max(1, n)
    min_length = max(1, min_length)
    max_length = max(min_length, max_length)
    min_frequency = max(1, min_frequency)
    max_frequency = max(min_frequency, max_frequency)

    # Use a rapidly changing nonce for gaps and a slower one for frequencies to avoid reuse
    now_ts = datetime.now().timestamp()
    gap_rng = _build_drbg(seed, salt=struct.pack("d", float(now_ts)))
    freq_rng = _build_drbg(seed, salt=datetime.now().strftime("%Y-%m").encode("utf-8"))

    gaps = [gap_rng.randint(min_length, max_length) for _ in range(max(0, n - 1))]
    frequencies = [freq_rng.randint(min_frequency, max_frequency) for _ in range(n)]

    return jsonify(
        {
            "gaps": gaps,
            "frequencies": frequencies,
            "duration": duration,
            "sample_rate": sample_rate,
            "count": n,
        }
    )

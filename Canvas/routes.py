import base64
import hashlib
import io
import os
import string
import struct
from datetime import datetime
from typing import Dict, List, Tuple

import flask
from PIL import Image
from flask import Blueprint, jsonify, request

from drbg import HMACDRBG

canvas_bp = Blueprint(
    "canvas",
    __name__,
    template_folder="templates",
    static_folder="static",
)

# Matches the standalone canvas_server entropy to keep identical behaviour.
entropy = b"0\x01\xe5`\xf1&\xf1\x93\xab\x10Ol\x0ezw^\xea}\xe2#\xc4\xd8s^\x1bk\x0c\xcd\x07S\x08\r"
print(entropy)

# Store draw configurations keyed by seed bytes so the upload route can reuse them.
db = {}

# Ensure debug crops can be written just like the reference server.
_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upload")
os.makedirs(_UPLOAD_DIR, exist_ok=True)


def map_bytes_to_string(data: bytes, num_emojis: int = 1) -> str:
    """
    Map each byte deterministically to a character.
    The resulting string has the same length as the input bytes.

    The last `num_emojis` characters are emojis,
    the preceding characters are from letters + digits + special chars.
    """
    if num_emojis < 0 or num_emojis > len(data):
        raise ValueError("num_emojis must be between 0 and len(data)")

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    specials = string.digits + "!@#$%^&*()-_=+[]{};:,.<>/? "
    main_chars = uppercase + lowercase + specials
    emojis = ["😀", "😎", "🚀", "🔥", "✨", "💡", "✅", "🎉", "❤️", "🐍"]

    result = []
    cutoff = len(data) - num_emojis
    for b in data[:cutoff]:
        result.append(main_chars[b % len(main_chars)])
    for b in data[cutoff:]:
        result.append(emojis[b % len(emojis)])
    return "".join(result)


def tighten_image(img: Image.Image, threshold: int = 245) -> Image.Image:
    """
    Remove surrounding whitespace from a cropped canvas row.

    If an alpha channel exists we use it directly. Otherwise fall back to a
    grayscale mask that treats near-white pixels as background.
    """

    if "A" in img.getbands():
        alpha = img.split()[-1]
        bbox = alpha.getbbox()
        if bbox and bbox != (0, 0, img.width, img.height):
            return img.crop(bbox)

    rgb_img = img.convert("RGB")
    gray = rgb_img.convert("L")
    # Anything darker than the threshold is considered foreground.
    mask = gray.point(lambda px: 255 if px < threshold else 0)
    bbox = mask.getbbox()
    return rgb_img.crop(bbox) if bbox else rgb_img


@canvas_bp.route("/")
def index():
    return flask.send_file("Canvas/index.html")


@canvas_bp.route("/get_string_config/<string:seed>/<int:n>/<int:width>/<int:height>")
def get_string_config(seed: str, n: int, width: int, height: int):
    seed_bytes = seed.encode("utf-8")
    drbg_positions = HMACDRBG(
        entropy_input=entropy,
        nonce=struct.pack("d", float(datetime.now().timestamp())),
        personalization_string=seed_bytes,
    )
    drbg_strings = HMACDRBG(
        entropy_input=entropy,
        nonce=datetime.now().strftime("%Y-%m").encode("utf-8"),
        personalization_string=seed_bytes,
    )

    strings: List[str] = []
    xs: List[int] = []
    ys: List[int] = []
    y_cursor = 25

    for _ in range(n):
        x = drbg_positions.randint(2, width - 32 * 30)
        delta_y = drbg_positions.randint(40, 100)
        y_cursor += delta_y
        xs.append(x)
        ys.append(y_cursor)
        strings.append(map_bytes_to_string(drbg_strings.generate(32), 1))

    db[seed_bytes] = (strings, xs, ys)
    return jsonify({"strings": strings, "xs": xs, "ys": ys, "font": "20px Arial"})


@canvas_bp.route("/upload_img/<string:seed>", methods=["POST"])
def upload_img(seed: str):
    seed_bytes = seed.encode("utf-8")
    challenge = db.get(seed_bytes)
    if challenge is None:
        return jsonify({"error": "Seed not found"}), 404

    payload = request.get_json(silent=True) or {}
    data_url = payload.get("data")
    if not data_url:
        return jsonify({"error": "No image data provided"}), 400
    try:
        _, encoded = data_url.split(",", 1)
    except ValueError:
        return jsonify({"error": "Invalid data URL"}), 400

    try:
        raw_bytes = base64.b64decode(encoded)
        img = Image.open(io.BytesIO(raw_bytes))

    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Invalid image data: {exc}"}), 400

    strings, xs, ys = challenge
    hashes: List[str] = []
    FONT_SIZE = 20
    TOP_PADDING = 4
    BOTTOM_PADDING = 10
    for string_val, x_pos, y_pos in zip(strings, xs, ys):
        top = max(0, y_pos - TOP_PADDING)
        bottom = min(img.height, y_pos + FONT_SIZE + BOTTOM_PADDING)
        cropped_img = img.crop((0, top, img.width, bottom))
        tightened_img = tighten_image(cropped_img)
        hash_value = hashlib.sha256(tightened_img.tobytes()).hexdigest()
        hashes.append(hash_value)
        print(string_val, hash_value)

    final_hash = hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()
    return jsonify({"message": "Image uploaded successfully", "hash": final_hash})

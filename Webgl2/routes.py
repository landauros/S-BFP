import base64
import hmac
import hashlib
import io
import flask
from typing import Optional, List, Tuple
from flask import jsonify, request, Blueprint, render_template, json
import os, struct
from datetime import datetime
import math
from PIL import Image
import numpy as np
from scipy import ndimage


class HMACDRBG:
    """
    NIST SP 800-90A HMAC-DRBG (SHA-256) with (K, V) state.
    - Instantiate(entropy_input, nonce, personalization_string)
    - Reseed(entropy_input, additional_input)
    - Generate(n_bytes, additional_input)
    Also exposes randint(a, b) with rejection sampling (uniform, no modulo bias).
    """

    def __init__(
        self,
        entropy_input: bytes,
        nonce: bytes = b"",
        personalization_string: bytes = b"",
        reseed_interval: int = 2**48,  # per spec (practically "very large")
    ):
        self._hash = hashlib.sha256
        self._outlen = self._hash().digest_size  # 32 bytes for SHA-256
        # 10.1.2.3 Instantiate Process
        self.K = b"\x00" * self._outlen
        self.V = b"\x01" * self._outlen
        seed_material = entropy_input + nonce + personalization_string
        self._update(seed_material)
        self.reseed_counter = 1
        self.reseed_interval = reseed_interval

    # --- Internal helpers (spec 10.1.2.2 Update Function) ---
    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, self._hash).digest()

    def _update(self, provided_data: Optional[bytes]):
        # K = HMAC(K, V || 0x00 || provided_data)
        # V = HMAC(K, V)
        if provided_data is None:
            provided_data = b""
        self.K = self._hmac(self.K, self.V + b"\x00" + provided_data)
        self.V = self._hmac(self.K, self.V)

        if len(provided_data) > 0:
            # K = HMAC(K, V || 0x01 || provided_data)
            # V = HMAC(K, V)
            self.K = self._hmac(self.K, self.V + b"\x01" + provided_data)
            self.V = self._hmac(self.K, self.V)

    # --- Public API ---

    def reseed(self, entropy_input: bytes, additional_input: bytes = b""):
        """
        10.1.2.4 Reseed Process
        """
        seed_material = entropy_input + additional_input
        self._update(seed_material)
        self.reseed_counter = 1

    def generate(self, n_bytes: int, additional_input: bytes = b"") -> bytes:
        """
        10.1.2.5 Generate Process
        - Optionally mixes additional_input before generating
        - Optionally performs an additional update after generation if additional_input is non-empty
        """
        if self.reseed_counter > self.reseed_interval:
            raise RuntimeError(
                "Reseed required (reseed_counter exceeded reseed_interval)."
            )

        if additional_input:
            # K = HMAC(K, V || 0x00 || additional_input); V = HMAC(K, V)
            self.K = self._hmac(self.K, self.V + b"\x00" + additional_input)
            self.V = self._hmac(self.K, self.V)

        # Produce pseudorandom bytes
        temp = bytearray()
        while len(temp) < n_bytes:
            self.V = self._hmac(self.K, self.V)
            temp += self.V

        returned_bits = bytes(temp[:n_bytes])

        if additional_input:
            # Post-generation update (if additional_input provided)
            self.K = self._hmac(self.K, self.V + b"\x00" + additional_input)
            self.V = self._hmac(self.K, self.V)

        self.reseed_counter += 1
        return returned_bits

    # --- Convenience on top of Generate() ---

    def randint(self, a: int, b: int) -> int:
        """
        Returns a uniform integer in [a, b] using rejection sampling (no modulo bias).
        """
        if a > b:
            raise ValueError("a must be <= b")
        span = b - a + 1
        if span <= 0:
            # Shouldn't happen for finite ints, but just in case
            raise ValueError("Invalid span")

        # Determine how many bytes we need to cover the span
        # We draw k bytes => 0..(2^(8k)-1). Accept if within limit, else retry.
        # limit = floor((2^(8k) / span)) * span - 1
        # Choose smallest k such that 2^(8k) >= span
        k = 1
        while (1 << (8 * k)) < span:
            k += 1

        space = 1 << (8 * k)
        limit = (space // span) * span - 1

        while True:
            r = int.from_bytes(self.generate(k), "big")
            if r <= limit:
                return a + (r % span)

    def random_float(self) -> float:
        """
        Return a uniform float in [0.0, 1.0) with 53 bits of precision.
        """
        # 7 bytes = 56 bits; we only need 53
        raw = int.from_bytes(self.generate(7), "big")
        x = raw >> 3  # discard 3 high bits
        return x / (1 << 53)

    def uniform(self, a: float, b: float) -> float:
        """
        Return a uniform float in [a, b).
        """
        return a + (b - a) * self.random_float()

    def random_bytes(self, n: int) -> bytes:
        return self.generate(n)


class AABB:
    __slots__ = ("x0", "y0", "x1", "y1")

    def __init__(self, x0, y0, x1, y1):
        if x1 < x0 or y1 < y0:
            raise ValueError("Invalid AABB: (x1,y1) must be >= (x0,y0)")
        self.x0, self.y0, self.x1, self.y1 = x0, y0, x1, y1

    def intersects(self, other):
        # Half-open boxes: edges touching do NOT count as intersection.
        return not (
            self.x1 <= other.x0
            or self.x0 >= other.x1
            or self.y1 <= other.y0
            or self.y0 >= other.y1
        )

    def contains_aabb(self, other):
        # Full containment (half-open convention).
        return (
            self.x0 <= other.x0
            and self.y0 <= other.y0
            and self.x1 >= other.x1
            and self.y1 >= other.y1
        )

    def contains_point(self, x, y):
        return (self.x0 <= x < self.x1) and (self.y0 <= y < self.y1)


class Quadtree:
    __slots__ = (
        "boundary",
        "capacity",
        "depth",
        "max_depth",
        "items",
        "divided",
        "nw",
        "ne",
        "sw",
        "se",
    )

    def __init__(self, boundary, capacity=4, depth=0, max_depth=10):
        self.boundary = boundary  # AABB
        self.capacity = capacity
        self.depth = depth
        self.max_depth = max_depth

        self.items = []  # list of (AABB, data)
        self.divided = False
        self.nw = self.ne = self.sw = self.se = None

    def subdivide(self):
        x0, y0, x1, y1 = (
            self.boundary.x0,
            self.boundary.y0,
            self.boundary.x1,
            self.boundary.y1,
        )
        mx = (x0 + x1) / 2.0
        my = (y0 + y1) / 2.0

        self.nw = Quadtree(
            AABB(x0, y0, mx, my), self.capacity, self.depth + 1, self.max_depth
        )
        self.ne = Quadtree(
            AABB(mx, y0, x1, my), self.capacity, self.depth + 1, self.max_depth
        )
        self.sw = Quadtree(
            AABB(x0, my, mx, y1), self.capacity, self.depth + 1, self.max_depth
        )
        self.se = Quadtree(
            AABB(mx, my, x1, y1), self.capacity, self.depth + 1, self.max_depth
        )
        self.divided = True

    def _child_for(self, aabb):
        """Return a child node that fully contains `aabb`, or None if it spans multiple."""
        if not self.divided:
            return None
        for child in (self.nw, self.ne, self.sw, self.se):
            if child.boundary.contains_aabb(aabb):
                return child
        return None

    def _maybe_split_and_push_down(self):
        """Subdivide if needed and push down items that now fit in a child."""
        if (
            self.divided
            or (len(self.items) <= self.capacity)
            or (self.depth >= self.max_depth)
        ):
            return
        self.subdivide()
        kept = []
        for aabb, data in self.items:
            child = self._child_for(aabb)
            if child is not None:
                child.insert(aabb, data)
            else:
                kept.append((aabb, data))
        self.items = kept

    def insert(self, aabb, data):
        # Option A: reject if not even overlapping the global boundary (fast path).
        if not self.boundary.intersects(aabb) and not self.boundary.contains_aabb(aabb):
            return False

        # If we can place deeper, try to do so.
        if self.divided:
            child = self._child_for(aabb)
            if child is not None:
                return child.insert(aabb, data)

        # Store here.
        self.items.append((aabb, data))

        # If over capacity, split and push down.
        self._maybe_split_and_push_down()
        return True

    def query(self, range_aabb, found=None):
        if found is None:
            found = []

        if not self.boundary.intersects(range_aabb):
            return found

        # Collect from this node
        for aabb, data in self.items:
            if aabb.intersects(range_aabb):
                found.append((aabb, data))

        # Search children
        if self.divided:
            self.nw.query(range_aabb, found)
            self.ne.query(range_aabb, found)
            self.sw.query(range_aabb, found)
            self.se.query(range_aabb, found)

        return found

    def query_point(self, x, y, found=None):
        if found is None:
            found = []
        if not self.boundary.contains_point(x, y):
            return found

        for aabb, data in self.items:
            if aabb.contains_point(x, y):
                found.append((aabb, data))

        if self.divided:
            for child in (self.nw, self.ne, self.sw, self.se):
                child.query_point(x, y, found)
        return found


def generate_triangle_in_region(
    drbg_pos, drbg_shape, x0, y0, x1, y1, margin=2, box_width=64, box_height=64
):
    """
    Generate a triangle in a region.
    @param drbg_pos: The first DRBG. Encodes timestamp when the request is received. Determines the position of the triangle in the region.
    @param drbg_shape: The second DRBG. Encodes the current month and preliminary fingerprint from user device.Determines shape of the triangle.
    @param x0: The x-coordinate of the top-left corner of the region.
    @param y0: The y-coordinate of the top-left corner of the region.
    @param x1: The x-coordinate of the bottom-right corner of the region.
    @param y1: The y-coordinate of the bottom-right corner of the region.
    @param margin: The margin inside the region.
    @param box_width: The max width of the box that contains the triangle.
    @param box_height: The max height of the box that contains the triangle.
    @return: A list of 3 points representing the triangle.
    """
    # static triangle
    triangle = [
        0,
        55,
        17.38389009393539,
        0.67781283689527,
        39.3956816724991,
        8.0780276923631,
    ]

    x_offset = drbg_pos.randint(x0 + margin, x1 - margin - box_width)
    y_offset = drbg_pos.randint(y0 + margin + box_height, y1 - margin - box_height)
    triangle[0] += x_offset
    triangle[1] += y_offset
    triangle[2] += x_offset
    triangle[3] += y_offset
    triangle[4] += x_offset
    triangle[5] += y_offset

    # # Generates a random position for the left most vertex.
    # triangle = [
    #     drbg_pos.randint(x0 + margin, x1 - margin - box_width),
    #     drbg_pos.randint(y0 + margin + box_height, y1 - margin - box_height),
    # ] * 3
    # # Adds two random vertices to the right of the left most vertex.
    # # for i in range(1, 3):
    # #     triangle[i * 2] += drbg_shape.uniform(8, box_width)
    # #     triangle[i * 2 + 1] += drbg_shape.uniform(-box_height, box_height)
    # triangle[2] += drbg_shape.uniform(1, box_width)
    # triangle[5] += drbg_shape.uniform(-box_height, box_height)

    bbox = [
        math.floor(min(triangle[0], triangle[2], triangle[4]) - margin),
        math.floor(min(triangle[1], triangle[3], triangle[5]) - margin),
        math.ceil(max(triangle[0], triangle[2], triangle[4]) + margin),
        math.ceil(max(triangle[1], triangle[3], triangle[5]) + margin),
    ]
    return triangle, bbox


def generate_non_overlapping_triangles_quadtree(
    drbg_pos, drbg_shape, n, width, height, triangle_size=64
):
    """
    Generate n non-overlapping triangles.
    """
    triangles = []
    bboxes = []
    quadtree = Quadtree(AABB(0, 0, width, height))
    max_attempts = n * 10  # Maximum attempts to avoid infinite loops
    attempts = 0

    if triangle_size > width or triangle_size * 2 > height:
        raise ValueError("Triangle size is too large for the canvas")

    current_triangle = None
    while len(triangles) < n and attempts < max_attempts:
        current_triangle, bbox = generate_triangle_in_region(
            drbg_pos,
            drbg_shape,
            0,
            0,
            width,
            height,
            margin=2,
            box_width=triangle_size,
            box_height=triangle_size,
        )
        x_offset = 0
        y_offset = 0

        overlap = False
        while attempts < max_attempts:
            bbox[0] += x_offset
            bbox[1] += y_offset
            bbox[2] += x_offset
            bbox[3] += y_offset

            current_triangle[0] += x_offset
            current_triangle[1] += y_offset
            current_triangle[2] += x_offset
            current_triangle[3] += y_offset
            current_triangle[4] += x_offset
            current_triangle[5] += y_offset

            overlapping_items = quadtree.query(AABB(bbox[0], bbox[1], bbox[2], bbox[3]))
            overlap = len(overlapping_items) > 0

            if overlap:
                x_offset = drbg_pos.randint(-bbox[0], width - bbox[2])
                y_offset = drbg_pos.randint(-bbox[1], height - bbox[3])
                attempts += 1
            else:
                break

        if not overlap:
            triangles.append(current_triangle)
            bboxes.append(bbox)
            quadtree.insert(AABB(bbox[0], bbox[1], bbox[2], bbox[3]), current_triangle)

    if len(triangles) < n:
        raise ValueError("Failed to generate non-overlapping triangles")

    return triangles, bboxes


def tighten_image(img: Image.Image) -> Image.Image:
    """Trim transparent borders from an RGBA image."""
    rgba_img = img.convert("RGBA")
    alpha_channel = rgba_img.split()[3]
    bbox = alpha_channel.getbbox()
    return rgba_img.crop(bbox) if bbox else rgba_img


entropy = b"o\xd6\xb6m\xd0{\xbfRy\xbc[\xa2\x1f\xb8\x0c\x92\xb4z+\x9b\xf7c\xdf\xf2\xd9\x1fhP\xf6h4\xdb"  # os.urandom(32)
db = {}
# app = flask.Flask(__name__)
webgl2_bp = Blueprint(
    "webgl2", __name__, template_folder="templates", static_folder="static"
)


@webgl2_bp.route("/")
def index():
    return flask.send_file("Webgl2/stability.html")


@webgl2_bp.route("/utils/<path:filename>")
def serve_utils(filename):
    return flask.send_file(f"Webgl2/utils/{filename}")


@webgl2_bp.route("/preliminary_fingerprint.js")
def serve_fingerprint():
    return flask.send_file("Webgl2/preliminary_fingerprint.js")


@webgl2_bp.route("/get_triangle/<string:seed>/<int:width>/<int:height>")
def get_triangle(seed, width, height):
    seed = seed.encode("utf-8")
    timestamp = str(datetime.now().timestamp())
    drbg_pos = HMACDRBG(
        entropy_input=entropy,
        nonce=struct.pack("d", float(timestamp)),
        personalization_string=seed,
    )

    drbg_shape = HMACDRBG(
        entropy_input=entropy,
        nonce=datetime.now().strftime("%Y-%m").encode("utf-8"),
        personalization_string=seed,
    )

    triangle, _ = generate_triangle_in_region(
        drbg_pos, drbg_shape, 0, 0, width, height, 3, 64, 64
    )

    return jsonify({"triangle": triangle})


@webgl2_bp.route("/get_triangles/<int:n>/<string:seed>/<int:width>/<int:height>")
def get_triangles(n, seed, width, height):
    seed = seed.encode("utf-8")
    timestamp = str(datetime.now().timestamp())
    drbg_pos = HMACDRBG(
        entropy_input=entropy,
        nonce=struct.pack("d", float(timestamp)),
        personalization_string=seed,
    )
    drbg_shape = HMACDRBG(
        entropy_input=entropy,
        nonce=datetime.now().strftime("%Y-%m").encode("utf-8"),
        personalization_string=seed,
    )

    # Generate non-overlapping triangles using quadtree overlapping testing
    try:
        triangles, bboxes = generate_non_overlapping_triangles_quadtree(
            drbg_pos, drbg_shape, n, width, height
        )
        db[seed] = bboxes
        return jsonify({"triangle": triangles})
    except Exception as e:
        return jsonify({"error": f"Error generating triangles: {str(e)}"}), 500


def _load_users():
    """加载用户列表"""
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


@webgl2_bp.route("/upload_img/<string:seed>", methods=["POST"])
def upload_img(seed):
    seed = seed.encode("utf-8")
    if seed not in db:
        return jsonify({"error": "Seed not found"}), 404
    data_url = request.get_data()
    if not data_url:
        return jsonify({"error": "No image data provided"}), 400

    try:
        if data_url.startswith(b"data:image"):
            # Find the comma and get the base64 part
            comma_index = data_url.find(b",")
            if comma_index != -1:
                encoded = data_url[comma_index + 1 :]
    except ValueError:
        return jsonify({"error": "Invalid data URL"}), 400

    try:
        raw_bytes = base64.b64decode(encoded)
        img = Image.open(io.BytesIO(raw_bytes))
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Invalid image data: {exc}"}), 400

    segment_hashes = []
    for bbox in db[seed]:
        cropped_img = img.crop(bbox)
        tightened_img = tighten_image(cropped_img)
        segment_hashes.append(hashlib.sha256(tightened_img.tobytes()).hexdigest())

    combined_hash = hashlib.sha256("".join(sorted(segment_hashes)).encode()).hexdigest()
    return jsonify(
        {
            "message": "Image uploaded successfully",
            "hash": combined_hash,
            "individual_hashes": segment_hashes,
        }
    )


# webgl2_bp.run(debug=False, port=5000, host="0.0.0.0")

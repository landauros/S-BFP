import hmac
import hashlib
import flask
from typing import Optional
from flask import jsonify
import os, struct
from datetime import datetime


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


# -------------------------------
# Example usage
# -------------------------------
if __name__ == "__main__":
    # # You should supply high-quality entropy_input and nonce.
    # # For deterministic testing, fixed bytes are fine; for real use, draw from os.urandom.
    # # true random input, secret seed
    # entropy = b"example-entropy-32+bytes-is-good---"
    # # updated regularly (per month or something)
    # nonce = b"2025-11"
    # # Input from preliminary fingerprinting
    # pers = b"asdf"

    # drbg = HMACDRBG(entropy_input=entropy, nonce=nonce, personalization_string=pers)

    # # # Generate bytes
    # # token = drbg.generate(16)  # 16 pseudorandom bytes
    # # print("bytes:", token.hex())

    # # # Uniform integers in [0, 10]
    # # ints = [drbg.randint(0, 10) for _ in range(20)]
    # # print("ints:", ints)

    # floats = [drbg.uniform(0, 20) for _ in range(3)]
    # print("floats:", floats)

    # Reseed when desired (e.g., new entropy)
    # drbg.reseed(entropy_input=b"fresh-entropy", additional_input=b"optional-AAD")
    # print("post-reseed byte:", drbg.generate(1).hex())
    entropy = os.urandom(32)
    app = flask.Flask(__name__)

    @app.route("/")
    def index():
        return flask.send_file("stability.html")

    @app.route("/utils/<path:filename>")
    def serve_utils(filename):
        return flask.send_file(f"utils/{filename}")

    @app.route("/preliminary_fingerprint.js")
    def serve_fingerprint():
        return flask.send_file("preliminary_fingerprint.js")

    @app.route("/get_triangle/<string:seed>/<int:max_width>/<int:max_height>")
    def get_triangle(seed, max_width, max_height):
        seed = seed.encode("utf-8")
        timestamp = str(datetime.now().timestamp())
        drbg1 = HMACDRBG(
            entropy_input=entropy,
            nonce=struct.pack("d", float(timestamp)),
            personalization_string=seed,
        )
        triangle = [
            drbg1.randint(0, max_width - 64),
            drbg1.randint(64, max_height - 64),
        ] * 3

        drbg2 = HMACDRBG(
            entropy_input=entropy,
            nonce=datetime.now().strftime("%Y-%m").encode("utf-8"),
            personalization_string=seed,
        )
        for i in range(1, 3):
            triangle[i * 2] += drbg2.uniform(8, 64)
            triangle[i * 2 + 1] += drbg2.uniform(-64, 64)

        return jsonify({"triangle": triangle})

    app.run(debug=True, port=5000, host="0.0.0.0")

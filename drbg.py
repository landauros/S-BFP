import hmac
import hashlib
from typing import Optional


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

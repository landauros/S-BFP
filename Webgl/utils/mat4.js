/* Minimal column-major 4x4 matrix helpers used by the S-BFP WebGL demo. */
var mat4 = (() => {
  function create() {
    const out = new Float32Array(16);
    out[0] = 1;
    out[5] = 1;
    out[10] = 1;
    out[15] = 1;
    return out;
  }

  function translate(out, a, vector) {
    const x = vector[0];
    const y = vector[1];
    const z = vector[2];
    if (out !== a) {
      for (let i = 0; i < 12; i += 1) out[i] = a[i];
    }
    out[12] = a[0] * x + a[4] * y + a[8] * z + a[12];
    out[13] = a[1] * x + a[5] * y + a[9] * z + a[13];
    out[14] = a[2] * x + a[6] * y + a[10] * z + a[14];
    out[15] = a[3] * x + a[7] * y + a[11] * z + a[15];
    return out;
  }

  function scale(out, a, vector) {
    const x = vector[0];
    const y = vector[1];
    const z = vector[2];
    out[0] = a[0] * x;
    out[1] = a[1] * x;
    out[2] = a[2] * x;
    out[3] = a[3] * x;
    out[4] = a[4] * y;
    out[5] = a[5] * y;
    out[6] = a[6] * y;
    out[7] = a[7] * y;
    out[8] = a[8] * z;
    out[9] = a[9] * z;
    out[10] = a[10] * z;
    out[11] = a[11] * z;
    out[12] = a[12];
    out[13] = a[13];
    out[14] = a[14];
    out[15] = a[15];
    return out;
  }

  function rotate(out, a, radians, axis) {
    let x = axis[0];
    let y = axis[1];
    let z = axis[2];
    const length = Math.hypot(x, y, z);
    if (length < Number.EPSILON) return null;
    x /= length;
    y /= length;
    z /= length;

    const sine = Math.sin(radians);
    const cosine = Math.cos(radians);
    const t = 1 - cosine;
    const b00 = x * x * t + cosine;
    const b01 = y * x * t + z * sine;
    const b02 = z * x * t - y * sine;
    const b10 = x * y * t - z * sine;
    const b11 = y * y * t + cosine;
    const b12 = z * y * t + x * sine;
    const b20 = x * z * t + y * sine;
    const b21 = y * z * t - x * sine;
    const b22 = z * z * t + cosine;

    const a00 = a[0], a01 = a[1], a02 = a[2], a03 = a[3];
    const a10 = a[4], a11 = a[5], a12 = a[6], a13 = a[7];
    const a20 = a[8], a21 = a[9], a22 = a[10], a23 = a[11];

    out[0] = a00 * b00 + a10 * b01 + a20 * b02;
    out[1] = a01 * b00 + a11 * b01 + a21 * b02;
    out[2] = a02 * b00 + a12 * b01 + a22 * b02;
    out[3] = a03 * b00 + a13 * b01 + a23 * b02;
    out[4] = a00 * b10 + a10 * b11 + a20 * b12;
    out[5] = a01 * b10 + a11 * b11 + a21 * b12;
    out[6] = a02 * b10 + a12 * b11 + a22 * b12;
    out[7] = a03 * b10 + a13 * b11 + a23 * b12;
    out[8] = a00 * b20 + a10 * b21 + a20 * b22;
    out[9] = a01 * b20 + a11 * b21 + a21 * b22;
    out[10] = a02 * b20 + a12 * b21 + a22 * b22;
    out[11] = a03 * b20 + a13 * b21 + a23 * b22;

    if (out !== a) {
      out[12] = a[12];
      out[13] = a[13];
      out[14] = a[14];
      out[15] = a[15];
    }
    return out;
  }

  return Object.freeze({ create, rotate, scale, translate });
})();

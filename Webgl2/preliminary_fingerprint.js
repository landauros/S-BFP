/**
 * Preliminary Fingerprinting Script
 * Collects basic browser and system information to create a unique seed
 * for the DRBG (Deterministic Random Bit Generator)
 */

export async function getPreliminaryFingerprint() {
  const fingerprint = {
    // User Agent string
    userAgent: navigator.userAgent,

    // Screen information
    screenWidth: screen.width,
    screenHeight: screen.height,
    screenColorDepth: screen.colorDepth,
    screenPixelDepth: screen.pixelDepth,

    // Timezone
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),

    // Language
    language: navigator.language,
    languages: navigator.languages
      ? navigator.languages.join(",")
      : navigator.language,

    // Platform
    platform: navigator.platform,

    // Hardware concurrency (number of CPU cores)
    hardwareConcurrency: navigator.hardwareConcurrency,

    // Canvas fingerprint (basic)
    canvasFingerprint: getCanvasFingerprint(),

    // WebGL vendor and renderer
    webglInfo: getWebGLInfo(),

    // WebGL fingerprint
    webglFingerprint: await getWebGLFingerprint(),
  };

  // Create a deterministic string from the fingerprint data
  const fingerprintString = createFingerprintString(fingerprint);

  return {
    raw: fingerprint,
    string: fingerprintString,
    hash: await hashFingerprint(fingerprintString),
  };
}

function getCanvasFingerprint() {
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");

    // Set canvas size
    canvas.width = 250;
    canvas.height = 50;

    // Draw some text and shapes
    const txt = "134cdd!$@#VDFH%^&^*&).\u2615";
    ctx.textBaseline = "top";
    ctx.font = "16px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.rotate(0.05);
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText(txt, 2, 15);
    ctx.fillStyle = "rgba(163, 42, 179, 0.7)";
    ctx.fillText(txt, 4, 17);
    ctx.shadowBlur = 10;
    ctx.shadowColor = "blue";
    ctx.fillRect(-20, 10, 234, 5);

    // Return canvas data URL
    return canvas.toDataURL();
  } catch (e) {
    return "canvas-error";
  }
}

function getWebGLInfo() {
  try {
    const canvas = document.createElement("canvas");
    const gl =
      canvas.getContext("webgl") || canvas.getContext("experimental-webgl");

    if (!gl) {
      return "webgl-not-supported";
    }

    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");

    return {
      vendor: debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
        : "unknown",
      renderer: debugInfo
        ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
        : "unknown",
      version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
    };
  } catch (e) {
    return "webgl-error";
  }
}

function getGLContext(canvas) {
  // try WebGL2 first, fallback to WebGL1
  return (
    canvas.getContext("webgl2", { preserveDrawingBuffer: true }) ||
    canvas.getContext("webgl", { preserveDrawingBuffer: true }) ||
    canvas.getContext("experimental-webgl", { preserveDrawingBuffer: true })
  );
}

function compileShader(gl, type, source) {
  const s = gl.createShader(type);
  gl.shaderSource(s, source);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    const info = gl.getShaderInfoLog(s);
    gl.deleteShader(s);
    throw new Error("Shader compile error: " + info);
  }
  return s;
}

function makeFingerprintProgram(gl) {
  // Vertex shader (simple passthrough)
  const vs = `
    attribute vec2 a_position;
    varying vec2 v_uv;
    void main() {
      v_uv = (a_position + 1.0) * 0.5;
      gl_Position = vec4(a_position, 0, 1);
    }
  `;
  // Fragment shader: mix of trig, float ops to surface implementation differences
  const fs = `
    precision highp float;
    varying vec2 v_uv;
    uniform float u_time;
    // a few math ops to provoke different GPU/driver behaviors
    void main() {
      vec2 p = v_uv * 8.0;
      float r = length(p - vec2(4.0,4.0));
      float v = sin(p.x * 12.9898 + p.y * 78.233) * 43758.5453;
      v = fract(v) + 0.1 * cos(r * 3.1415 + u_time);
      // deliberately do some fractional indexing and small differences
      float a = floor(mod(v * 1000.0, 256.0));
      vec3 color = vec3(fract(v * 1.2345), fract(v * 2.3456), fract(v * 3.4567));
      gl_FragColor = vec4(color * (0.5 + 0.5 * sin(a + u_time)), 1.0);
    }
  `;

  const vsh = compileShader(gl, gl.VERTEX_SHADER, vs);
  const fsh = compileShader(gl, gl.FRAGMENT_SHADER, fs);

  const prog = gl.createProgram();
  gl.attachShader(prog, vsh);
  gl.attachShader(prog, fsh);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
    const info = gl.getProgramInfoLog(prog);
    throw new Error("Program link error: " + info);
  }
  return prog;
}

function renderPixels(gl, prog, width = 256, height = 256) {
  // setup full-screen triangle/quad
  const posLoc = gl.getAttribLocation(prog, "a_position");
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  // two triangles > full screen
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([-1, -1, 1, -1, -1, 1, 1, -1, 1, 1, -1, 1]),
    gl.STATIC_DRAW
  );

  gl.viewport(0, 0, width, height);
  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);

  gl.useProgram(prog);
  gl.enableVertexAttribArray(posLoc);
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

  // set uniform time to a deterministic value
  const tLoc = gl.getUniformLocation(prog, "u_time");
  if (tLoc) gl.uniform1f(tLoc, 1234.5678);

  gl.drawArrays(gl.TRIANGLES, 0, 6);

  // cleanup
  gl.deleteBuffer(buf);
}

async function getWebGLFingerprint({ imageSize = 128 } = {}) {
  const canvas = document.createElement("canvas");
  canvas.width = imageSize;
  canvas.height = imageSize;
  const gl = getGLContext(canvas);
  if (!gl) {
    return { error: "no-webgl", message: "WebGL not available or disabled" };
  }

  // attempt to render deterministic shader and get pixels
  try {
    const prog = makeFingerprintProgram(gl);
    renderPixels(gl, prog, imageSize, imageSize);
    // compute hash from raw pixel buffer
    gl.deleteProgram(prog);
  } catch (err) {
    return { error: "rendering-error", message: err.message };
  }

  return canvas.toDataURL("image/png");
}

function createFingerprintString(fingerprint) {
  // Create a deterministic string from the fingerprint data
  const components = [
    fingerprint.userAgent,
    `${fingerprint.screenWidth}x${fingerprint.screenHeight}`,
    `colorDepth:${fingerprint.screenColorDepth}`,
    `pixelDepth:${fingerprint.screenPixelDepth}`,
    fingerprint.timezone,
    `offset:${fingerprint.timezoneOffset}`,
    fingerprint.language,
    fingerprint.platform,
    `cores:${fingerprint.hardwareConcurrency}`,
    JSON.stringify(fingerprint.webglInfo),
    fingerprint.canvasFingerprint,
    fingerprint.webglFingerprint,
  ];

  return components.join("|");
}

async function hashFingerprint(fingerprintString) {
  try {
    // Use Web Crypto API to create a hash
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return hashHex;
  } catch (e) {
    // Fallback to simple hash if Web Crypto API is not available
    return simpleHash(fingerprintString);
  }
}

function simpleHash(str) {
  let hash = 0;
  if (str.length === 0) return hash.toString();

  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  return Math.abs(hash).toString(16);
}

// Export a function to get just the seed string for the API
export async function getSeedString() {
  const fingerprint = await getPreliminaryFingerprint();
  return fingerprint.hash;
}

// Export a function to get the full fingerprint for debugging
export async function getFullFingerprint() {
  return await getPreliminaryFingerprint();
}

/** Collect the browser seed used by the Canvas and Audio demos. */
export async function getPreliminaryFingerprint() {
  const fingerprint = {
    userAgent: navigator.userAgent,
    screenWidth: screen.width,
    screenHeight: screen.height,
    screenColorDepth: screen.colorDepth,
    screenPixelDepth: screen.pixelDepth,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    language: navigator.language,
    languages: navigator.languages
      ? navigator.languages.join(",")
      : navigator.language,
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    canvasFingerprint: getCanvasFingerprint(),
  };

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
    const context = canvas.getContext("2d");
    canvas.width = 250;
    canvas.height = 50;
    const text = "134cdd!$@#VDFH%^&^*&).☕";
    context.textBaseline = "alphabetic";
    context.font = "16px 'Arial'";
    context.rotate(0.05);
    context.fillStyle = "#f60";
    context.fillRect(125, 1, 62, 20);
    context.fillStyle = "#069";
    context.fillText(text, 2, 15);
    context.fillStyle = "rgba(163, 42, 179, 0.7)";
    context.fillText(text, 4, 17);
    context.shadowBlur = 10;
    context.shadowColor = "blue";
    context.fillRect(-20, 10, 234, 5);
    return canvas.toDataURL();
  } catch (error) {
    return "canvas-error";
  }
}

function createFingerprintString(fingerprint) {
  return [
    fingerprint.userAgent,
    `${fingerprint.screenWidth}x${fingerprint.screenHeight}`,
    `colorDepth:${fingerprint.screenColorDepth}`,
    `pixelDepth:${fingerprint.screenPixelDepth}`,
    fingerprint.timezone,
    `offset:${fingerprint.timezoneOffset}`,
    fingerprint.language,
    fingerprint.platform,
    `cores:${fingerprint.hardwareConcurrency}`,
    fingerprint.canvasFingerprint,
  ].join("|");
}

async function hashFingerprint(fingerprintString) {
  try {
    const data = new TextEncoder().encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
  } catch (error) {
    return simpleHash(fingerprintString);
  }
}

function simpleHash(value) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash &= hash;
  }
  return Math.abs(hash).toString(16);
}

export async function getSeedString() {
  const fingerprint = await getPreliminaryFingerprint();
  return fingerprint.hash;
}

export async function getFullFingerprint() {
  return getPreliminaryFingerprint();
}

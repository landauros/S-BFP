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

    // Browser extensions
    extensions: await getInstalledExtensions(),

    // Mathematical function results
    mathResults: getMathResults(),
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
    canvas.width = 200;
    canvas.height = 50;

    // Draw some text and shapes
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.font = "11px Arial";
    ctx.fillText("Canvas fingerprint", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.font = "18px Arial";
    ctx.fillText("Canvas fingerprint", 4, 45);

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

async function getInstalledExtensions() {
  const extensionFingerprint = {
    // Method Canvas: Check for common extension APIs and objects
    chromeExtensions: checkChromeExtensions(),
    firefoxExtensions: checkFirefoxExtensions(),

    // Method 2: Check for extension-specific global objects
    globalObjects: checkExtensionGlobals(),

    // Method 3: Check for extension-injected scripts
    injectedScripts: checkInjectedScripts(),

    // Method 4: Check for extension-specific CSS
    extensionCSS: checkExtensionCSS(),

    // Method 5: Check for extension-specific permissions
    permissions: await checkPermissions(),

    // Method 6: Check for extension-specific APIs
    extensionAPIs: checkExtensionAPIs(),
  };

  return extensionFingerprint;
}

function checkChromeExtensions() {
  const chromeExtensions = [];

  try {
    // Check for Chrome extension APIs
    if (typeof chrome !== "undefined" && chrome.runtime) {
      chromeExtensions.push("chrome-runtime");
    }

    // Check for common Chrome extension objects
    const chromeObjects = [
      "chrome.app",
      "chrome.extension",
      "chrome.runtime",
      "chrome.storage",
      "chrome.tabs",
      "chrome.windows",
    ];

    chromeObjects.forEach((obj) => {
      if (typeof window[obj] !== "undefined") {
        chromeExtensions.push(obj);
      }
    });

    // Check for extension-specific global variables
    const extensionVars = [
      "chrome_extension",
      "chrome_webstore",
      "chrome_extension_id",
    ];

    extensionVars.forEach((varName) => {
      if (typeof window[varName] !== "undefined") {
        chromeExtensions.push(varName);
      }
    });
  } catch (e) {
    chromeExtensions.push("chrome-check-error");
  }

  return chromeExtensions;
}

function checkFirefoxExtensions() {
  const firefoxExtensions = [];

  try {
    // Check for Firefox extension APIs
    if (typeof Components !== "undefined") {
      firefoxExtensions.push("firefox-components");
    }

    // Check for Firefox-specific extension objects
    const firefoxObjects = ["browser", "chrome", "Services"];

    firefoxObjects.forEach((obj) => {
      if (typeof window[obj] !== "undefined") {
        firefoxExtensions.push(obj);
      }
    });

    // Check for Firefox extension-specific variables
    const firefoxVars = ["gBrowser", "gBrowserInit", "gBrowserStartup"];

    firefoxVars.forEach((varName) => {
      if (typeof window[varName] !== "undefined") {
        firefoxExtensions.push(varName);
      }
    });
  } catch (e) {
    firefoxExtensions.push("firefox-check-error");
  }

  return firefoxExtensions;
}

function checkExtensionGlobals() {
  const globalObjects = [];

  try {
    // Check for extension-specific global objects
    const extensionGlobals = [
      "web3",
      "ethereum",
      "bitcoin",
      "MetaMask",
      "Trust",
      "CoinbaseWallet",
      "WalletConnect",
      "Phantom",
      "Solflare",
      "TronLink",
      "BinanceChain",
      "BraveWallet",
      "OperaWallet",
      "Exodus",
      "AtomicWallet",
      "MathWallet",
      "TokenPocket",
      "imToken",
      "BitKeep",
      "Rainbow",
      "Frame",
      "Rabby",
      "Zerion",
      "Argent",
      "Gnosis",
      "Safe",
      "Wallet3",
      "OneKey",
      "Tokenary",
      "WalletConnect",
      "WalletLink",
      "Fortmatic",
      "Portis",
      "Torus",
      "Authereum",
      "MewConnect",
      "Ledger",
      "Trezor",
      "KeepKey",
      "BitBox",
      "CoolWallet",
      "Ellipal",
      "Safepal",
      "Keystone",
      "GridPlus",
      "Dcent",
      "Bitfi",
      "Coolbitx",
      "SecuX",
      "BCVault",
      "NGRAVE",
      "Arculus",
      "Tangem",
      "Ellipal",
      "Safepal",
      "Keystone",
      "GridPlus",
      "Dcent",
      "Bitfi",
      "Coolbitx",
      "SecuX",
      "BCVault",
      "NGRAVE",
      "Arculus",
      "Tangem",
    ];

    extensionGlobals.forEach((globalName) => {
      if (typeof window[globalName] !== "undefined") {
        globalObjects.push(globalName);
      }
    });
  } catch (e) {
    globalObjects.push("global-check-error");
  }

  return globalObjects;
}

function checkInjectedScripts() {
  const injectedScripts = [];

  try {
    // Check for extension-injected scripts by looking at script tags
    const scripts = document.querySelectorAll("script");
    scripts.forEach((script) => {
      const src = script.src;
      if (src) {
        // Check for extension-specific URLs
        if (
          src.includes("chrome-extension://") ||
          src.includes("moz-extension://") ||
          src.includes("safari-extension://") ||
          src.includes("ms-browser-extension://")
        ) {
          injectedScripts.push(src);
        }
      }
    });

    // Check for extension-injected content scripts
    const extensionSelectors = [
      "[data-extension]",
      "[data-chrome-extension]",
      "[data-firefox-extension]",
      "[data-safari-extension]",
      "[data-edge-extension]",
    ];

    extensionSelectors.forEach((selector) => {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        injectedScripts.push(selector);
      }
    });
  } catch (e) {
    injectedScripts.push("injected-scripts-error");
  }

  return injectedScripts;
}

function checkExtensionCSS() {
  const extensionCSS = [];

  try {
    // Check for extension-specific CSS classes and styles
    const extensionClasses = [
      "chrome-extension",
      "firefox-extension",
      "safari-extension",
      "edge-extension",
      "browser-extension",
      "web-extension",
    ];

    extensionClasses.forEach((className) => {
      const elements = document.querySelectorAll(`.${className}`);
      if (elements.length > 0) {
        extensionCSS.push(className);
      }
    });

    // Check for extension-specific CSS variables
    const computedStyle = getComputedStyle(document.documentElement);
    const extensionVars = [
      "--chrome-extension",
      "--firefox-extension",
      "--safari-extension",
      "--edge-extension",
    ];

    extensionVars.forEach((varName) => {
      const value = computedStyle.getPropertyValue(varName);
      if (value && value.trim() !== "") {
        extensionCSS.push(varName);
      }
    });
  } catch (e) {
    extensionCSS.push("extension-css-error");
  }

  return extensionCSS;
}

async function checkPermissions() {
  const permissions = [];

  try {
    // Check for various permissions that extensions might request
    const permissionChecks = [
      "geolocation",
      "camera",
      "microphone",
      "notifications",
      "clipboard-read",
      "clipboard-write",
      "payment",
      "usb",
      "serial",
      "bluetooth",
      "nfc",
      "accelerometer",
      "gyroscope",
      "magnetometer",
      "ambient-light-sensor",
      "proximity",
      "ambient-light-sensor",
      "gyroscope",
      "magnetometer",
      "accelerometer",
    ];

    for (const permission of permissionChecks) {
      try {
        const result = await navigator.permissions.query({ name: permission });
        if (result.state === "granted") {
          permissions.push(permission);
        }
      } catch (e) {
        // Permission not supported or denied
      }
    }
  } catch (e) {
    permissions.push("permissions-check-error");
  }

  return permissions;
}

function checkExtensionAPIs() {
  const extensionAPIs = [];

  try {
    // Check for extension-specific APIs
    const extensionAPIChecks = [
      "chrome.runtime",
      "chrome.tabs",
      "chrome.windows",
      "chrome.storage",
      "chrome.cookies",
      "chrome.history",
      "chrome.bookmarks",
      "chrome.downloads",
      "chrome.management",
      "chrome.permissions",
      "chrome.identity",
      "chrome.oauth",
      "chrome.alarms",
      "chrome.notifications",
      "chrome.contextMenus",
      "chrome.commands",
      "chrome.omnibox",
      "chrome.declarativeContent",
      "chrome.webRequest",
      "chrome.webNavigation",
      "chrome.tabs.query",
      "chrome.tabs.create",
      "chrome.tabs.update",
      "chrome.tabs.remove",
      "chrome.windows.create",
      "chrome.windows.update",
      "chrome.windows.remove",
      "chrome.storage.local",
      "chrome.storage.sync",
      "chrome.storage.session",
      "chrome.storage.managed",
      "chrome.cookies.get",
      "chrome.cookies.set",
      "chrome.cookies.remove",
      "chrome.history.search",
      "chrome.history.addUrl",
      "chrome.history.deleteUrl",
      "chrome.history.deleteRange",
      "chrome.history.deleteAll",
      "chrome.bookmarks.get",
      "chrome.bookmarks.create",
      "chrome.bookmarks.update",
      "chrome.bookmarks.remove",
      "chrome.downloads.download",
      "chrome.downloads.search",
      "chrome.downloads.pause",
      "chrome.downloads.resume",
      "chrome.downloads.cancel",
      "chrome.downloads.erase",
      "chrome.management.get",
      "chrome.management.getAll",
      "chrome.management.getSelf",
      "chrome.management.setEnabled",
      "chrome.management.uninstall",
      "chrome.permissions.contains",
      "chrome.permissions.request",
      "chrome.permissions.remove",
      "chrome.identity.getAuthToken",
      "chrome.identity.getProfileUserInfo",
      "chrome.identity.removeCachedAuthToken",
      "chrome.oauth.getAccessToken",
      "chrome.alarms.create",
      "chrome.alarms.get",
      "chrome.alarms.getAll",
      "chrome.alarms.clear",
      "chrome.alarms.clearAll",
      "chrome.notifications.create",
      "chrome.notifications.get",
      "chrome.notifications.getAll",
      "chrome.notifications.clear",
      "chrome.notifications.clearAll",
      "chrome.contextMenus.create",
      "chrome.contextMenus.update",
      "chrome.contextMenus.remove",
      "chrome.contextMenus.removeAll",
      "chrome.commands.getAll",
      "chrome.omnibox.setDefaultSuggestion",
      "chrome.omnibox.onInputChanged",
      "chrome.omnibox.onInputEntered",
      "chrome.omnibox.onInputStarted",
      "chrome.omnibox.onInputCancelled",
      "chrome.declarativeContent.onPageChanged",
      "chrome.webRequest.onBeforeRequest",
      "chrome.webRequest.onBeforeSendHeaders",
      "chrome.webRequest.onSendHeaders",
      "chrome.webRequest.onHeadersReceived",
      "chrome.webRequest.onAuthRequired",
      "chrome.webRequest.onResponseStarted",
      "chrome.webRequest.onBeforeRedirect",
      "chrome.webRequest.onCompleted",
      "chrome.webRequest.onErrorOccurred",
      "chrome.webNavigation.onBeforeNavigate",
      "chrome.webNavigation.onCommitted",
      "chrome.webNavigation.onDOMContentLoaded",
      "chrome.webNavigation.onCompleted",
      "chrome.webNavigation.onCreatedNavigationTarget",
      "chrome.webNavigation.onReferenceFragmentUpdated",
      "chrome.webNavigation.onTabReplaced",
      "chrome.webNavigation.onHistoryStateUpdated",
    ];

    extensionAPIChecks.forEach((api) => {
      try {
        const parts = api.split(".");
        let obj = window;
        for (const part of parts) {
          if (obj && typeof obj[part] !== "undefined") {
            obj = obj[part];
          } else {
            obj = null;
            break;
          }
        }
        if (obj !== null) {
          extensionAPIs.push(api);
        }
      } catch (e) {
        // API not available
      }
    });
  } catch (e) {
    extensionAPIs.push("extension-apis-error");
  }

  return extensionAPIs;
}

function getMathResults() {
  const mathResults = {};

  try {
    // Basic trigonometric functions
    mathResults.sin = {
      sin0: Math.sin(0),
      sinPi2: Math.sin(Math.PI / 2),
      sinPi: Math.sin(Math.PI),
      sin3Pi2: Math.sin((3 * Math.PI) / 2),
      sin2Pi: Math.sin(2 * Math.PI),
      sin1: Math.sin(1),
      sinNeg1: Math.sin(-1),
      sinInf: Math.sin(Infinity),
      sinNegInf: Math.sin(-Infinity),
      sinNaN: Math.sin(NaN),
    };

    mathResults.cos = {
      cos0: Math.cos(0),
      cosPi2: Math.cos(Math.PI / 2),
      cosPi: Math.cos(Math.PI),
      cos3Pi2: Math.cos((3 * Math.PI) / 2),
      cos2Pi: Math.cos(2 * Math.PI),
      cos1: Math.cos(1),
      cosNeg1: Math.cos(-1),
      cosInf: Math.cos(Infinity),
      cosNegInf: Math.cos(-Infinity),
      cosNaN: Math.cos(NaN),
    };

    mathResults.tan = {
      tan0: Math.tan(0),
      tanPi4: Math.tan(Math.PI / 4),
      tanPi2: Math.tan(Math.PI / 2),
      tanPi: Math.tan(Math.PI),
      tan1: Math.tan(1),
      tanNeg1: Math.tan(-1),
      tanInf: Math.tan(Infinity),
      tanNegInf: Math.tan(-Infinity),
      tanNaN: Math.tan(NaN),
    };

    // Inverse trigonometric functions
    mathResults.asin = {
      asin0: Math.asin(0),
      asin1: Math.asin(1),
      asinNeg1: Math.asin(-1),
      asin2: Math.asin(2),
      asinNeg2: Math.asin(-2),
      asinInf: Math.asin(Infinity),
      asinNegInf: Math.asin(-Infinity),
      asinNaN: Math.asin(NaN),
    };

    mathResults.acos = {
      acos0: Math.acos(0),
      acos1: Math.acos(1),
      acosNeg1: Math.acos(-1),
      acos2: Math.acos(2),
      acosNeg2: Math.acos(-2),
      acosInf: Math.acos(Infinity),
      acosNegInf: Math.acos(-Infinity),
      acosNaN: Math.acos(NaN),
    };

    mathResults.atan = {
      atan0: Math.atan(0),
      atan1: Math.atan(1),
      atanNeg1: Math.atan(-1),
      atanInf: Math.atan(Infinity),
      atanNegInf: Math.atan(-Infinity),
      atanNaN: Math.atan(NaN),
    };

    // Hyperbolic functions
    mathResults.sinh = {
      sinh0: Math.sinh(0),
      sinh1: Math.sinh(1),
      sinhNeg1: Math.sinh(-1),
      sinhInf: Math.sinh(Infinity),
      sinhNegInf: Math.sinh(-Infinity),
      sinhNaN: Math.sinh(NaN),
    };

    mathResults.cosh = {
      cosh0: Math.cosh(0),
      cosh1: Math.cosh(1),
      coshNeg1: Math.cosh(-1),
      coshInf: Math.cosh(Infinity),
      coshNegInf: Math.cosh(-Infinity),
      coshNaN: Math.cosh(NaN),
    };

    mathResults.tanh = {
      tanh0: Math.tanh(0),
      tanh1: Math.tanh(1),
      tanhNeg1: Math.tanh(-1),
      tanhInf: Math.tanh(Infinity),
      tanhNegInf: Math.tanh(-Infinity),
      tanhNaN: Math.tanh(NaN),
    };

    // Logarithmic functions
    mathResults.log = {
      log1: Math.log(1),
      logE: Math.log(Math.E),
      log10: Math.log(10),
      log0: Math.log(0),
      logNeg1: Math.log(-1),
      logInf: Math.log(Infinity),
      logNegInf: Math.log(-Infinity),
      logNaN: Math.log(NaN),
    };

    mathResults.log10 = {
      log10_1: Math.log10(1),
      log10_10: Math.log10(10),
      log10_100: Math.log10(100),
      log10_0: Math.log10(0),
      log10_Neg1: Math.log10(-1),
      log10_Inf: Math.log10(Infinity),
      log10_NegInf: Math.log10(-Infinity),
      log10_NaN: Math.log10(NaN),
    };

    mathResults.log2 = {
      log2_1: Math.log2(1),
      log2_2: Math.log2(2),
      log2_8: Math.log2(8),
      log2_0: Math.log2(0),
      log2_Neg1: Math.log2(-1),
      log2_Inf: Math.log2(Infinity),
      log2_NegInf: Math.log2(-Infinity),
      log2_NaN: Math.log2(NaN),
    };

    // Exponential functions
    mathResults.exp = {
      exp0: Math.exp(0),
      exp1: Math.exp(1),
      expNeg1: Math.exp(-1),
      expInf: Math.exp(Infinity),
      expNegInf: Math.exp(-Infinity),
      expNaN: Math.exp(NaN),
    };

    mathResults.expm1 = {
      expm1_0: Math.expm1(0),
      expm1_1: Math.expm1(1),
      expm1_Neg1: Math.expm1(-1),
      expm1_Inf: Math.expm1(Infinity),
      expm1_NegInf: Math.expm1(-Infinity),
      expm1_NaN: Math.expm1(NaN),
    };

    // Power functions
    mathResults.pow = {
      pow2_3: Math.pow(2, 3),
      pow3_2: Math.pow(3, 2),
      pow0_0: Math.pow(0, 0),
      pow1_Inf: Math.pow(1, Infinity),
      powInf_0: Math.pow(Infinity, 0),
      powNeg1_2: Math.pow(-1, 2),
      powNeg1_3: Math.pow(-1, 3),
      powNaN_1: Math.pow(NaN, 1),
      pow1_NaN: Math.pow(1, NaN),
    };

    mathResults.sqrt = {
      sqrt0: Math.sqrt(0),
      sqrt1: Math.sqrt(1),
      sqrt4: Math.sqrt(4),
      sqrt9: Math.sqrt(9),
      sqrtNeg1: Math.sqrt(-1),
      sqrtInf: Math.sqrt(Infinity),
      sqrtNegInf: Math.sqrt(-Infinity),
      sqrtNaN: Math.sqrt(NaN),
    };

    mathResults.cbrt = {
      cbrt0: Math.cbrt(0),
      cbrt1: Math.cbrt(1),
      cbrt8: Math.cbrt(8),
      cbrtNeg8: Math.cbrt(-8),
      cbrtInf: Math.cbrt(Infinity),
      cbrtNegInf: Math.cbrt(-Infinity),
      cbrtNaN: Math.cbrt(NaN),
    };

    // Rounding functions
    mathResults.round = {
      round0_5: Math.round(0.5),
      roundNeg0_5: Math.round(-0.5),
      round1_5: Math.round(1.5),
      roundNeg1_5: Math.round(-1.5),
      roundInf: Math.round(Infinity),
      roundNegInf: Math.round(-Infinity),
      roundNaN: Math.round(NaN),
    };

    mathResults.floor = {
      floor0_5: Math.floor(0.5),
      floorNeg0_5: Math.floor(-0.5),
      floor1_5: Math.floor(1.5),
      floorNeg1_5: Math.floor(-1.5),
      floorInf: Math.floor(Infinity),
      floorNegInf: Math.floor(-Infinity),
      floorNaN: Math.floor(NaN),
    };

    mathResults.ceil = {
      ceil0_5: Math.ceil(0.5),
      ceilNeg0_5: Math.ceil(-0.5),
      ceil1_5: Math.ceil(1.5),
      ceilNeg1_5: Math.ceil(-1.5),
      ceilInf: Math.ceil(Infinity),
      ceilNegInf: Math.ceil(-Infinity),
      ceilNaN: Math.ceil(NaN),
    };

    mathResults.trunc = {
      trunc0_5: Math.trunc(0.5),
      truncNeg0_5: Math.trunc(-0.5),
      trunc1_5: Math.trunc(1.5),
      truncNeg1_5: Math.trunc(-1.5),
      truncInf: Math.trunc(Infinity),
      truncNegInf: Math.trunc(-Infinity),
      truncNaN: Math.trunc(NaN),
    };

    // Special values and constants
    mathResults.constants = {
      PI: Math.PI,
      E: Math.E,
      LN2: Math.LN2,
      LN10: Math.LN10,
      LOG2E: Math.LOG2E,
      LOG10E: Math.LOG10E,
      SQRT1_2: Math.SQRT1_2,
      SQRT2: Math.SQRT2,
    };

    // Random number generation (seeded for consistency)
    const originalRandom = Math.random;
    Math.random = () => 0.5; // Fixed seed for consistency
    mathResults.random = {
      random1: Math.random(),
      random2: Math.random(),
      random3: Math.random(),
    };
    Math.random = originalRandom; // Restore original

    // Precision tests
    mathResults.precision = {
      epsilon: Number.EPSILON,
      maxSafeInteger: Number.MAX_SAFE_INTEGER,
      minSafeInteger: Number.MIN_SAFE_INTEGER,
      maxValue: Number.MAX_VALUE,
      minValue: Number.MIN_VALUE,
      positiveInfinity: Number.POSITIVE_INFINITY,
      negativeInfinity: Number.NEGATIVE_INFINITY,
      nan: Number.NaN,
    };

    // Floating point arithmetic precision
    mathResults.arithmetic = {
      add: 0.1 + 0.2,
      sub: 0.3 - 0.1,
      mul: 0.1 * 3,
      div: 1 / 3,
      mod: 10 % 3,
      pow: 2 ** 3,
      sqrt2: Math.sqrt(2),
      pi: Math.PI,
      e: Math.E,
    };
  } catch (e) {
    mathResults.error = "math-results-error";
  }

  return mathResults;
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
    JSON.stringify(fingerprint.webglInfo).substring(0, 100), // First 100 chars of WebGL info
    JSON.stringify(fingerprint.extensions).substring(0, 200), // First 200 chars of extension info
    JSON.stringify(fingerprint.mathResults).substring(0, 300), // First 300 chars of math results
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

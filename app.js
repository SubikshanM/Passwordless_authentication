// --- Cybersecurity Passwordless Auth App ---

// Helper: base32 decode to bytes for Web Crypto API
function base32ToBytes(base32) {
  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  base32 = base32.replace(/=+$/, "").toUpperCase();
  const len = base32.length;
  const bytes = new Uint8Array(Math.floor((len * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;

  for (let i = 0; i < len; i++) {
    const val = base32chars.indexOf(base32[i]);
    if (val === -1) throw new Error("Invalid base32 character: " + base32[i]);
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bytes[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return bytes;
}

// Generate standard TOTP 6-digit code
async function generateTOTP(secretBase32, timeStep = 30) {
  try {
    const keyBytes = base32ToBytes(secretBase32);
    
    // Get counter (8-byte big endian array)
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / timeStep);
    const counterBytes = new Uint8Array(8);
    let temp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = temp & 0xff;
      temp = Math.floor(temp / 256);
    }

    // Import the raw key for HMAC SHA-1
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: "SHA-1" } },
      false,
      ["sign"]
    );

    // Compute HMAC
    const signature = await window.crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      counterBytes
    );

    const hmacBytes = new Uint8Array(signature);
    
    // Dynamic truncation
    const offset = hmacBytes[hmacBytes.length - 1] & 0xf;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const otp = binary % 1000000;
    return otp.toString().padStart(6, "0");
  } catch (err) {
    console.error("Error generating TOTP: ", err);
    return null;
  }
}

// Validate user-entered TOTP (check current, previous, and next step to allow clock drift)
async function verifyTOTP(secretBase32, enteredCode) {
  const steps = [0, -1, 1]; // Allow 30 seconds drift back or forward
  for (const stepOffset of steps) {
    const epoch = Math.floor(Date.now() / 1000) + (stepOffset * 30);
    const counter = Math.floor(epoch / 30);
    const counterBytes = new Uint8Array(8);
    let temp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = temp & 0xff;
      temp = Math.floor(temp / 256);
    }

    const keyBytes = base32ToBytes(secretBase32);
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: { name: "SHA-1" } },
      false,
      ["sign"]
    );

    const signature = await window.crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      counterBytes
    );

    const hmacBytes = new Uint8Array(signature);
    const offset = hmacBytes[hmacBytes.length - 1] & 0xf;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const otp = (binary % 1000000).toString().padStart(6, "0");
    if (otp === enteredCode) {
      return true;
    }
  }
  return false;
}

// Generate random base32 secret (16 chars)
function generateBase32Secret() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let secret = "";
  for (let i = 0; i < 16; i++) {
    secret += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return secret;
}

// Global state for captcha
let captchaVerified = false;

// Setup Google reCAPTCHA System
async function setupCaptcha(onVerifySuccess) {
  const container = document.getElementById("recaptcha-container");
  if (!container) return;

  // Retrieve Site Key from .env
  let siteKey = "6LfBNiItAAAAAI4LaGJoiAvxEslTae1kaJai_do2"; // Default fallback
  try {
    const response = await fetch(".env");
    if (response.ok) {
      const text = await response.text();
      const match = text.match(/RECAPTCHA_SITE_KEY\s*=\s*([^\s]+)/);
      if (match && match[1]) {
        siteKey = match[1].trim();
      }
    }
  } catch (err) {
    console.warn("Could not read .env file, using default site key.", err);
  }

  // Load Google reCAPTCHA API Script dynamically if not already loaded
  if (typeof grecaptcha === "undefined") {
    const script = document.createElement("script");
    script.src = "https://www.google.com/recaptcha/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);

    script.onload = () => {
      renderWidget(siteKey, onVerifySuccess);
    };
  } else {
    renderWidget(siteKey, onVerifySuccess);
  }
}

function renderWidget(siteKey, onVerifySuccess) {
  if (typeof grecaptcha !== "undefined") {
    grecaptcha.ready(() => {
      // Clear any existing contents in the container to avoid duplicate rendering
      const container = document.getElementById("recaptcha-container");
      if (container) container.innerHTML = "";
      
      grecaptcha.render("recaptcha-container", {
        sitekey: siteKey,
        theme: "dark", // Using dark theme to match cybersecurity design
        callback: (token) => {
          captchaVerified = true;
          showNotification("Captcha solved successfully.", "success");
          if (onVerifySuccess) onVerifySuccess();
        },
        "expired-callback": () => {
          captchaVerified = false;
          showNotification("Captcha expired. Please verify again.", "error");
          if (onVerifySuccess) onVerifySuccess();
        },
        "error-callback": () => {
          captchaVerified = false;
          showNotification("reCAPTCHA error encountered. Please reload.", "error");
          if (onVerifySuccess) onVerifySuccess();
        }
      });
    });
  }
}

// Helper: Show alert/notification bar
function showNotification(message, type = "error") {
  const notif = document.getElementById("notification");
  if (!notif) return;
  notif.textContent = message;
  notif.className = "notification show " + type;
  setTimeout(() => {
    notif.className = "notification";
  }, 4000);
}

// Copy to Clipboard
function setupCopyToClipboard() {
  const copyBtn = document.getElementById("copyBtn");
  const secretText = document.getElementById("secretKey");
  if (!copyBtn || !secretText) return;

  copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(secretText.textContent)
      .then(() => {
        const origIcon = copyBtn.innerHTML;
        copyBtn.innerHTML = "✓";
        copyBtn.style.color = "var(--accent-green)";
        setTimeout(() => {
          copyBtn.innerHTML = origIcon;
          copyBtn.style.color = "";
        }, 1500);
      })
      .catch(err => {
        console.error("Failed to copy secret: ", err);
      });
  });
}

// Auto-advance OTP inputs and handle backspace
function setupOtpInputs(onSubmit) {
  const inputs = document.querySelectorAll(".otp-input");
  if (inputs.length === 0) return;

  inputs.forEach((input, index) => {
    input.addEventListener("input", (e) => {
      // Allow only numbers
      const value = e.target.value;
      if (!/^\d*$/.test(value)) {
        e.target.value = "";
        return;
      }

      if (value.length > 0) {
        // Limit to 1 character
        e.target.value = value.substring(0, 1);
        
        // Auto focus next
        if (index < inputs.length - 1) {
          inputs[index + 1].focus();
        }
      }

      // Check if all entered
      const allFilled = Array.from(inputs).every(inp => inp.value !== "");
      if (allFilled && onSubmit) {
        const fullCode = Array.from(inputs).map(inp => inp.value).join("");
        onSubmit(fullCode);
      }
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Backspace") {
        if (input.value === "" && index > 0) {
          inputs[index - 1].focus();
          inputs[index - 1].value = "";
        } else {
          input.value = "";
        }
      }
    });

    // Handle paste event
    input.addEventListener("paste", (e) => {
      e.preventDefault();
      const pastedData = e.clipboardData.getData("text").trim();
      if (!/^\d{6}$/.test(pastedData)) return;

      inputs.forEach((inp, idx) => {
        inp.value = pastedData[idx] || "";
      });

      inputs[inputs.length - 1].focus();
      
      if (onSubmit) {
        onSubmit(pastedData);
      }
    });
  });
}

// Clear OTP inputs
function clearOtpInputs() {
  const inputs = document.querySelectorAll(".otp-input");
  inputs.forEach(inp => inp.value = "");
  if (inputs[0]) inputs[0].focus();
}

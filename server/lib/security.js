import crypto from "node:crypto";

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function encryptionKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("SESSION_SECRET must be configured with at least 32 characters.");
  }
  return crypto.createHash("sha256").update(`${secret}:zerotrust:mfa:v1`).digest();
}

export function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}

export function decryptSecret(value) {
  const [iv, tag, payload] = value.split(".");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(payload, "base64url")), decipher.final()]).toString("utf8");
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newTotpSecret(bytes = 20) {
  const input = crypto.randomBytes(bytes);
  let bits = "";
  for (const byte of input) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i < bits.length; i += 5) {
    output += base32Alphabet[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  }
  return output;
}

function decodeBase32(value) {
  const clean = value.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of clean) bits += base32Alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totpAt(secret, counter) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", decodeBase32(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

export function generateTotp(secret, now = Date.now()) {
  return totpAt(secret, Math.floor(now / 30_000));
}

export function verifyTotp(secret, code, now = Date.now()) {
  if (!/^\d{6}$/.test(String(code))) return false;
  const counter = Math.floor(now / 30_000);
  const candidate = Buffer.from(String(code));
  for (let delta = -1; delta <= 1; delta += 1) {
    const expected = Buffer.from(totpAt(secret, counter + delta));
    if (candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected)) return true;
  }
  return false;
}

export function totpUri(secret, email) {
  const label = encodeURIComponent(`ZeroTrust:${email}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=ZeroTrust&algorithm=SHA1&digits=6&period=30`;
}

export function requestContext(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const ipAddress = (typeof forwarded === "string" ? forwarded.split(",")[0].trim() : req.ip || "").slice(0, 80);
  const agent = String(req.headers["user-agent"] || "Unknown browser").slice(0, 300);
  const browser = /Edg\//.test(agent) ? "Edge" : /Chrome\//.test(agent) ? "Chrome" : /Firefox\//.test(agent) ? "Firefox" : /Safari\//.test(agent) ? "Safari" : "Unknown browser";
  const operatingSystem = /Windows/i.test(agent) ? "Windows" : /Mac OS X/i.test(agent) ? "macOS" : /Android/i.test(agent) ? "Android" : /iPhone|iPad/i.test(agent) ? "iOS" : /Linux/i.test(agent) ? "Linux" : "Unknown OS";
  return { ipAddress, browser, operatingSystem, deviceName: `${browser} on ${operatingSystem}` };
}

export function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true" || process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    ...(maxAge ? { maxAge } : {}),
  };
}

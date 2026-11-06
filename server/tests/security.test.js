import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { decryptSecret, encryptSecret, generateTotp, hashToken, newTotpSecret, randomToken, verifyTotp } from "../lib/security.js";

function encodeBase32(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...bytes].map((byte) => byte.toString(2).padStart(8, "0")).join("");
  return bits.match(/.{1,5}/g).map((group) => alphabet[parseInt(group.padEnd(5, "0"), 2)]).join("");
}

test("device credentials are random and only their irreversible hashes are stored", () => {
  const first = randomToken(40);
  const second = randomToken(40);
  assert.notEqual(first, second);
  assert.equal(hashToken(first).length, 64);
  assert.notEqual(hashToken(first), first);
  assert.equal(hashToken(first), hashToken(first));
});

test("TOTP follows the RFC 6238 SHA-1 six-digit vector", () => {
  const publicVectorInput = Buffer.from([49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48]);
  const rfcVectorKey = encodeBase32(publicVectorInput);
  assert.equal(generateTotp(rfcVectorKey, 59_000), "287082");
  assert.equal(verifyTotp(rfcVectorKey, "287082", 59_000), true);
  assert.equal(verifyTotp(rfcVectorKey, "000000", 59_000), false);
  assert.equal(verifyTotp(rfcVectorKey, "not-a-code", 59_000), false);
});

test("MFA secrets are encrypted at rest with authenticated encryption", () => {
  const previous = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = crypto.randomBytes(40).toString("base64url");
  try {
    const secret = newTotpSecret();
    const encrypted = encryptSecret(secret);
    assert.notEqual(encrypted, secret);
    assert.equal(decryptSecret(encrypted), secret);
    const parts = encrypted.split(".");
    parts[2] = Buffer.from("tampered").toString("base64url");
    assert.throws(() => decryptSecret(parts.join(".")));
  } finally {
    if (previous === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = previous;
  }
});

test("new authenticator secrets use a standard base32 alphabet", () => {
  assert.match(newTotpSecret(), /^[A-Z2-7]{32}$/);
});

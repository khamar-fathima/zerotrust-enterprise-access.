import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { decryptSecret, encryptSecret, generateTotp, hashToken, newTotpSecret, randomToken, verifyTotp } from "../lib/security.js";

test("device credentials are random and only their irreversible hashes are stored", () => {
  const first = randomToken(40);
  const second = randomToken(40);
  assert.notEqual(first, second);
  assert.equal(hashToken(first).length, 64);
  assert.notEqual(hashToken(first), first);
  assert.equal(hashToken(first), hashToken(first));
});

test("TOTP follows the RFC 6238 SHA-1 six-digit vector", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(generateTotp(secret, 59_000), "287082");
  assert.equal(verifyTotp(secret, "287082", 59_000), true);
  assert.equal(verifyTotp(secret, "000000", 59_000), false);
  assert.equal(verifyTotp(secret, "not-a-code", 59_000), false);
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

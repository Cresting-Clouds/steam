"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { verifyReference } = require("../src/reference");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const keyId = "test-key-2026-08-08";
const keys = { [keyId]: publicKey.export({ type: "spki", format: "pem" }) };
const now = 1_786_147_200_000;

function sign(payload, header = { alg: "RS256", kid: keyId, typ: "CCREF" }, key = privateKey) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.sign("RSA-SHA256", Buffer.from(`${encodedHeader}.${encodedPayload}`), key);
  return `${encodedHeader}.${encodedPayload}.${signature.toString("base64url")}`;
}

function runtimePayload(overrides = {}) {
  return {
    type: "cresting-clouds-steam",
    version: 1,
    aud: "cresting-clouds-steam",
    purpose: "runtime",
    jti: "ticket-12345678",
    iat: Math.floor(now / 1000) - 5,
    exp: Math.floor(now / 1000) + 300,
    repository: "customer/repository",
    redeem_url: "https://example.invalid/api/runtime",
    oidc_audience: "cresting-clouds-runtime",
    ...overrides,
  };
}

test("verifies a bounded RS256 runtime reference", () => {
  const result = verifyReference(sign(runtimePayload()), { keys, nowMs: now });
  assert.equal(result.header.kid, keyId);
  assert.equal(result.payload.purpose, "runtime");
});

test("rejects an unknown algorithm and injected key location", () => {
  assert.throws(
    () => verifyReference(sign(runtimePayload(), { alg: "HS256", kid: keyId, typ: "CCREF" }), { keys, nowMs: now }),
    /unsupported_reference_algorithm/,
  );
  assert.throws(
    () => verifyReference(sign(runtimePayload(), { alg: "RS256", kid: keyId, typ: "CCREF", jku: "https://attacker.invalid/key" }), { keys, nowMs: now }),
    /unsupported_reference_header/,
  );
});

test("rejects unknown keys, invalid signatures, and expiry", () => {
  assert.throws(
    () => verifyReference(sign(runtimePayload(), { alg: "RS256", kid: "unknown-key", typ: "CCREF" }), { keys, nowMs: now }),
    /unknown_reference_key/,
  );
  const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  assert.throws(() => verifyReference(sign(runtimePayload(), undefined, other), { keys, nowMs: now }), /invalid_reference_signature/);
  assert.throws(
    () => verifyReference(sign(runtimePayload({
      iat: Math.floor(now / 1000) - 300,
      exp: Math.floor(now / 1000) - 120,
    })), { keys, nowMs: now }),
    /reference_expired/,
  );
});

test("keeps authorization references offline", () => {
  const payload = runtimePayload({
    purpose: "vscode-auth",
    artifact_name: "cresting-clouds-vscode-auth-nonce123",
    encrypted_grant: { alg: "RSA-OAEP-256", ciphertext: "opaque" },
  });
  delete payload.repository;
  delete payload.redeem_url;
  delete payload.oidc_audience;
  assert.equal(verifyReference(sign(payload), { keys, nowMs: now }).payload.purpose, "vscode-auth");

  payload.redeem_url = "https://example.invalid/api/runtime";
  assert.throws(() => verifyReference(sign(payload), { keys, nowMs: now }), /auth_reference_must_not_redeem/);
});

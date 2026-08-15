"use strict";

const crypto = require("node:crypto");
const { trustedNimbusPublicKeys } = require("./keys");

const REFERENCE_TYPE = "cresting-clouds-steam";
const REFERENCE_VERSION = 1;
const REFERENCE_AUDIENCE = "cresting-clouds-steam";
const CLOCK_SKEW_SECONDS = 60;
const MAX_REFERENCE_BYTES = 32 * 1024;
const MAX_LIFETIME_SECONDS = 10 * 60;
const SAFE_ID = /^[A-Za-z0-9._-]{8,200}$/;
const SAFE_REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function decodeSegment(segment, label) {
  if (!segment || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new Error(`invalid_${label}_encoding`);
  }
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new Error(`invalid_${label}_json`);
  }
}

function requireExactHeader(header) {
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    throw new Error("invalid_reference_header");
  }
  const fields = Object.keys(header).sort();
  if (fields.join(",") !== "alg,kid,typ") {
    throw new Error("unsupported_reference_header");
  }
  if (header.alg !== "RS256" || header.typ !== "CCREF") {
    throw new Error("unsupported_reference_algorithm");
  }
  if (typeof header.kid !== "string" || !SAFE_ID.test(header.kid)) {
    throw new Error("invalid_reference_key_id");
  }
}

function requireHttpsUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`invalid_${label}`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error(`invalid_${label}`);
  }
  return parsed.toString();
}

function validatePayload(payload, nowSeconds) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("invalid_reference_payload");
  }
  if (payload.type !== REFERENCE_TYPE || payload.version !== REFERENCE_VERSION) {
    throw new Error("unsupported_reference_schema");
  }
  if (payload.aud !== REFERENCE_AUDIENCE) {
    throw new Error("invalid_reference_audience");
  }
  if (!SAFE_ID.test(String(payload.jti || ""))) {
    throw new Error("invalid_reference_id");
  }
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) {
    throw new Error("invalid_reference_lifetime");
  }
  if (payload.exp <= payload.iat || payload.exp - payload.iat > MAX_LIFETIME_SECONDS) {
    throw new Error("invalid_reference_lifetime");
  }
  if (payload.iat > nowSeconds + CLOCK_SKEW_SECONDS) {
    throw new Error("reference_not_yet_valid");
  }
  if (payload.exp <= nowSeconds - CLOCK_SKEW_SECONDS) {
    throw new Error("reference_expired");
  }

  if (payload.purpose === "vscode-auth") {
    if (!SAFE_ID.test(String(payload.artifact_name || ""))) {
      throw new Error("invalid_reference_artifact");
    }
    if (!payload.encrypted_grant || typeof payload.encrypted_grant !== "object") {
      throw new Error("missing_encrypted_grant");
    }
    if (payload.redeem_url !== undefined) {
      throw new Error("auth_reference_must_not_redeem");
    }
  } else if (payload.purpose === "runtime") {
    if (!SAFE_REPOSITORY.test(String(payload.repository || ""))) {
      throw new Error("invalid_reference_repository");
    }
    payload.redeem_url = requireHttpsUrl(payload.redeem_url, "reference_redeem_url");
    if (typeof payload.oidc_audience !== "string" || !SAFE_ID.test(payload.oidc_audience)) {
      throw new Error("invalid_reference_oidc_audience");
    }
  } else {
    throw new Error("unsupported_reference_purpose");
  }
  return payload;
}

function verifyReference(reference, options = {}) {
  if (typeof reference !== "string" || !reference || Buffer.byteLength(reference) > MAX_REFERENCE_BYTES) {
    throw new Error("invalid_reference");
  }
  const segments = reference.split(".");
  if (segments.length !== 3) {
    throw new Error("invalid_reference");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeSegment(encodedHeader, "reference_header");
  requireExactHeader(header);
  const keys = options.keys || trustedNimbusPublicKeys;
  const publicKey = keys[header.kid];
  if (!publicKey) {
    throw new Error("unknown_reference_key");
  }
  if (!/^[A-Za-z0-9_-]+$/.test(encodedSignature || "")) {
    throw new Error("invalid_reference_signature");
  }
  const verified = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    Buffer.from(encodedSignature, "base64url"),
  );
  if (!verified) {
    throw new Error("invalid_reference_signature");
  }
  const payload = decodeSegment(encodedPayload, "reference_payload");
  const nowSeconds = Math.floor((options.nowMs === undefined ? Date.now() : options.nowMs) / 1000);
  return { header, payload: validatePayload(payload, nowSeconds) };
}

module.exports = {
  REFERENCE_AUDIENCE,
  REFERENCE_TYPE,
  REFERENCE_VERSION,
  verifyReference,
};

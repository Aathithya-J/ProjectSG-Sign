// api/webhook/singpass.js
// Receives the Singpass success-signing webhook (POST).
//
// Singpass POSTs a JSON body signed with their own JWS/JWT.
// The body contains { sign_request_id, signed_doc_url, signer_info? }.
//
// This handler:
//   1. Verifies the webhook signature using Singpass's public JWKS
//   2. Stores the result (in-memory here — swap for your DB)
//   3. Returns HTTP 200 to acknowledge

import crypto from 'crypto';

// ── In-memory store (replace with your DB / Redis / KV) ────────────────────
// Map<sign_request_id, { signed_doc_url, received_at, signer_info }>
const store = globalThis.__singpassWebhookStore ??= new Map();

// ── Singpass JWKS endpoints ─────────────────────────────────────────────────
const SINGPASS_JWKS_STAGING = 'https://staging.sign.singpass.gov.sg/.well-known/jwks.json';
const SINGPASS_JWKS_PROD = 'https://app.sign.singpass.gov.sg/.well-known/jwks.json';

let cachedJwks = null;
let jwksCachedAt = 0;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getSingpassJwks() {
  const now = Date.now();
  if (cachedJwks && now - jwksCachedAt < JWKS_TTL_MS) return cachedJwks;

  const jwksUrl = process.env.SINGPASS_ENV === 'production'
    ? SINGPASS_JWKS_PROD
    : SINGPASS_JWKS_STAGING;

  const res = await fetch(jwksUrl);
  if (!res.ok) throw new Error(`Failed to fetch Singpass JWKS: ${res.status}`);
  cachedJwks = await res.json();
  jwksCachedAt = now;
  return cachedJwks;
}

// ── Base64url helpers ────────────────────────────────────────────────────────

function base64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/').padEnd(
    str.length + ((4 - (str.length % 4)) % 4), '='
  );
  return Buffer.from(padded, 'base64');
}

// ── Verify a compact JWS signed by Singpass ──────────────────────────────────

async function verifyWebhookJws(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWS format');

  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(base64urlDecode(headerB64).toString());

  if (header.alg !== 'ES256') throw new Error(`Unexpected alg: ${header.alg}`);

  // Find matching key in Singpass JWKS
  const jwks = await getSingpassJwks();
  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error(`No matching kid in Singpass JWKS: ${header.kid}`);

  // Import public key
  const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });

  // Verify signature (ieee-p1363 = raw 64-byte r‖s)
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = base64urlDecode(sigB64);
  const valid = crypto.verify(
    'sha256',
    Buffer.from(signingInput),
    { key: pubKey, dsaEncoding: 'ieee-p1363' },
    sig
  );
  if (!valid) throw new Error('Webhook signature verification failed');

  return JSON.parse(base64urlDecode(payloadB64).toString());
}

// ── Main handler ─────────────────────────────────────────────────────────────

export const config = {
  api: { bodyParser: false },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Read raw body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks).toString('utf8');

    // Singpass sends the webhook as a compact JWS token in the body,
    // or as JSON with a "token" field — handle both
    let payload;
    try {
      // Try: raw body IS the compact JWS
      if (rawBody.trim().startsWith('ey')) {
        payload = await verifyWebhookJws(rawBody.trim());
      } else {
        // Try: JSON wrapper { token: "<jws>" }
        const parsed = JSON.parse(rawBody);
        if (parsed.token) {
          payload = await verifyWebhookJws(parsed.token);
        } else {
          // No signature available (e.g. local testing) — accept as plain JSON
          console.warn('Webhook received without JWS — accepting as plain JSON (dev mode)');
          payload = parsed;
        }
      }
    } catch (verifyErr) {
      console.error('Webhook verification failed:', verifyErr.message);
      return res.status(401).json({ error: 'Webhook verification failed', detail: verifyErr.message });
    }

    const { sign_request_id, signed_doc_url, signer_info } = payload;

    if (!sign_request_id) {
      return res.status(400).json({ error: 'Missing sign_request_id in webhook payload' });
    }

    // Persist result
    store.set(sign_request_id, {
      signed_doc_url: signed_doc_url ?? null,
      signer_info: signer_info ?? null,
      received_at: new Date().toISOString(),
    });

    console.log(`Webhook received for ${sign_request_id}: ${signed_doc_url}`);

    // Singpass expects HTTP 200 acknowledgement
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('webhook/singpass.js error', err);
    return res.status(500).json({ error: err.message });
  }
}

// ── Expose store for api/status.js to query (same serverless instance) ───────
export { store };
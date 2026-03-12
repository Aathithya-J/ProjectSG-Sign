// api/sign.js
// Receives a PDF upload from the frontend, builds a JWT per Sign V3 spec,
// POSTs raw PDF bytes to Singpass, and returns sign_request_id / signing_url / exchange_code.

import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// ─── helpers ────────────────────────────────────────────────────────────────

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Build a Sign V3 JWT.
 *
 * Verified structure from official docs example JWT:
 *   Header  : { "alg": "ES256", "kid": "<kid>" }   — NO "typ" field
 *   Payload : { client_id, doc_name, x, y, page, iat, jti }
 *              x / y / page are TOP-LEVEL fields — NO exp field
 *   Signature: ES256, IEEE P1363 format (raw 64-byte r‖s)
 */
function buildJwt({ clientId, docName, x, y, page, privateKeyPem, kid }) {
  // Header — alg + kid only, no typ
  const header = base64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid })));

  // Payload — top-level x, y, page; iat in seconds; jti as UUID; no exp
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(
    Buffer.from(
      JSON.stringify({
        client_id: clientId,
        doc_name: docName,
        x,
        y,
        page,
        iat: now,
        jti: uuidv4(),
      })
    )
  );

  const signingInput = `${header}.${payload}`;

  // Load key — no "type" specified, just pem + format
  const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });

  // Sign with SHA-256 + IEEE P1363 encoding (raw 64-byte r‖s, NOT DER)
  const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });

  return `${signingInput}.${base64url(sigBuf)}`;
}

// ─── main handler ───────────────────────────────────────────────────────────

export const config = {
  api: {
    bodyParser: false, // We read raw multipart manually
  },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // ── 1. Parse multipart form-data to extract the PDF ──────────────────
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    // Extract boundary from Content-Type header
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=([^\s;]+)/);
    if (!boundaryMatch) {
      return res.status(400).json({ error: 'Missing multipart boundary' });
    }
    const boundary = boundaryMatch[1];

    // Parse out the PDF part
    const pdfBuffer = extractFilePart(body, boundary);
    if (!pdfBuffer) {
      return res.status(400).json({ error: 'No PDF file found in form upload' });
    }

    // ── 2. Extract signing params from form fields ────────────────────────
    const fields = extractFormFields(body, boundary);
    const docName = fields.doc_name || 'document.pdf';
    const x = Number(fields.x ?? 1);
    const y = Number(fields.y ?? 1);
    const page = Number(fields.page ?? 1);

    // ── 3. Load environment variables ────────────────────────────────────
    const clientId = process.env.SINGPASS_CLIENT_ID;
    const kid = process.env.SINGPASS_KID;
    const rawPem = process.env.SINGPASS_PRIVATE_KEY_PEM;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    if (!clientId || !kid || !rawPem) {
      return res.status(500).json({ error: 'Missing Singpass environment variables' });
    }

    // Vercel stores multi-line PEM with literal \n — restore real newlines
    const privateKeyPem = rawPem.replace(/\\n/g, '\n');

    // ── 4. Build JWT ──────────────────────────────────────────────────────
    const jwt = buildJwt({ clientId, docName, x, y, page, privateKeyPem, kid });

    // ── 5. POST raw PDF bytes to Singpass ─────────────────────────────────
    //   Endpoint : POST /api/v3/sign-requests
    //   Headers  : Authorization: Bearer <jwt>
    //              Content-Type: application/octet-stream
    //   Body     : raw PDF bytes — nothing else
    const singpassBase = 'https://staging.sign.singpass.gov.sg/api/v3';
    const webhookUrl = webhookBase
      ? `${webhookBase}/api/webhook/singpass`
      : undefined;

    const singpassRes = await fetch(`${singpassBase}/sign-requests`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/octet-stream',
        ...(webhookUrl ? { 'X-Webhook-Url': webhookUrl } : {}),
      },
      body: pdfBuffer,
    });

    // ── 6. Handle response — success is HTTP 201 (also accept 200) ────────
    if (singpassRes.status !== 201 && singpassRes.status !== 200) {
      const errText = await singpassRes.text();
      console.error('Singpass error', singpassRes.status, errText);
      return res.status(502).json({
        error: 'Singpass API error',
        status: singpassRes.status,
        detail: errText,
      });
    }

    const data = await singpassRes.json();
    // Singpass returns: { sign_request_id, signing_url, exchange_code }
    return res.status(200).json({
      sign_request_id: data.sign_request_id,
      signing_url: data.signing_url,
      exchange_code: data.exchange_code,
    });
  } catch (err) {
    console.error('sign.js error', err);
    return res.status(500).json({ error: err.message });
  }
}

// ─── multipart helpers ───────────────────────────────────────────────────────

function extractFilePart(body, boundary) {
  const boundaryBuf = Buffer.from(`--${boundary}`);
  let start = 0;
  while (start < body.length) {
    const boundaryIdx = body.indexOf(boundaryBuf, start);
    if (boundaryIdx === -1) break;

    const headerStart = boundaryIdx + boundaryBuf.length + 2; // skip CRLF
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;

    const headerStr = body.slice(headerStart, headerEnd).toString('utf8');

    // Find the next boundary to delimit part body
    const nextBoundary = body.indexOf(boundaryBuf, headerEnd + 4);
    const partEnd = nextBoundary === -1 ? body.length : nextBoundary - 2; // trim trailing CRLF
    const partBody = body.slice(headerEnd + 4, partEnd);

    // Look for file part (Content-Type: application/pdf or filename=)
    if (
      headerStr.includes('filename=') ||
      headerStr.toLowerCase().includes('application/pdf') ||
      headerStr.toLowerCase().includes('application/octet-stream')
    ) {
      return partBody;
    }
    start = boundaryIdx + boundaryBuf.length;
  }
  return null;
}

function extractFormFields(body, boundary) {
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const fields = {};
  let start = 0;
  while (start < body.length) {
    const boundaryIdx = body.indexOf(boundaryBuf, start);
    if (boundaryIdx === -1) break;

    const headerStart = boundaryIdx + boundaryBuf.length + 2;
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;

    const headerStr = body.slice(headerStart, headerEnd).toString('utf8');
    const nextBoundary = body.indexOf(boundaryBuf, headerEnd + 4);
    const partEnd = nextBoundary === -1 ? body.length : nextBoundary - 2;
    const partBody = body.slice(headerEnd + 4, partEnd).toString('utf8').trim();

    // Only treat as text field if no filename= present
    if (!headerStr.includes('filename=')) {
      const nameMatch = headerStr.match(/name="([^"]+)"/);
      if (nameMatch) {
        fields[nameMatch[1]] = partBody;
      }
    }
    start = boundaryIdx + boundaryBuf.length;
  }
  return fields;
}
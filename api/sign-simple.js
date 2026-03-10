const crypto = require('crypto');
const https  = require('https');

// Singpass Sign V3 — verified from official docs
// Staging:    https://staging.sign.singpass.gov.sg/api/v3
// Production: https://app.sign.singpass.gov.sg/api/v3
const STAGING_URL = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL    = "https://app.sign.singpass.gov.sg/api/v3/sign-requests";

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")   return res.status(405).json({ error: "Method not allowed" });

  try {
    const clientId    = process.env.SINGPASS_CLIENT_ID;
    const pem         = (process.env.SINGPASS_PRIVATE_KEY_PEM || '').replace(/\\n/g, '\n');
    const kid         = process.env.SINGPASS_KID;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    if (!clientId || !pem || !kid) {
      return res.status(500).json({
        error: "Missing required environment variables",
        missing: { clientId: !clientId, pem: !pem, kid: !kid },
      });
    }

    // Read raw multipart body from browser form
    const chunks = [];
    await new Promise((resolve, reject) => {
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', resolve);
      req.on('error', reject);
    });
    const rawBody = Buffer.concat(chunks);

    // Parse multipart to extract PDF and form fields
    const contentType   = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    if (!boundaryMatch) {
      return res.status(400).json({ error: "No boundary in content-type" });
    }

    const boundary    = boundaryMatch[1];
    const boundaryBuf = Buffer.from(`--${boundary}`);
    const parts       = [];
    let start = 0;

    while (start < rawBody.length) {
      const bIdx = rawBody.indexOf(boundaryBuf, start);
      if (bIdx === -1) break;
      start = bIdx + boundaryBuf.length;
      if (rawBody[start] === 0x2d && rawBody[start + 1] === 0x2d) break;
      if (rawBody[start] === 0x0d) start += 2;
      const headerEnd = rawBody.indexOf(Buffer.from('\r\n\r\n'), start);
      if (headerEnd === -1) break;
      const headers = rawBody.slice(start, headerEnd).toString();
      start = headerEnd + 4;
      const nextBoundary = rawBody.indexOf(boundaryBuf, start);
      const content = rawBody.slice(start, nextBoundary !== -1 ? nextBoundary - 2 : undefined);
      parts.push({ headers, content });
      start = nextBoundary !== -1 ? nextBoundary : rawBody.length;
    }

    let pdfFile = null;
    let fileName = 'document.pdf';
    const fields = {};

    for (const part of parts) {
      const nameMatch     = part.headers.match(/name="([^"]+)"/);
      const filenameMatch = part.headers.match(/filename="([^"]+)"/);
      if (nameMatch) {
        const name = nameMatch[1];
        if (name === 'file' && filenameMatch) {
          pdfFile  = part.content;
          fileName = filenameMatch[1];
        } else {
          fields[name] = part.content.toString();
        }
      }
    }

    if (!pdfFile) {
      return res.status(400).json({ error: "No PDF file found in request" });
    }

    const isStaging = fields.staging !== '0';
    const apiUrl    = isStaging ? STAGING_URL : PROD_URL;

    // ── Build JWT ──────────────────────────────────────────────────────────────
    // Verified against the exact example JWT in Singpass docs:
    //
    // HEADER: { "alg": "ES256", "kid": "<kid>" }
    //   - NO "typ" field
    //
    // PAYLOAD (single sig): { client_id, doc_name, x, y, page, iat, jti }
    //   - x, y, page are TOP-LEVEL fields, NOT nested in sign_locations
    //   - NO "exp" field
    //   - optional: signer_uin_hash, webhook_url
    //
    const now = Math.floor(Date.now() / 1000);
    const jwtPayload = {
      client_id: clientId,
      doc_name:  fields.doc_name || fileName,
      x:    0.72,
      y:    0.05,
      page: 1,
      iat:  now,
      jti:  crypto.randomUUID(),
    };

    if (webhookBase) {
      jwtPayload.webhook_url = `${webhookBase}/api/webhook/singpass`;
    }

    if (fields.signer_nric) {
      jwtPayload.signer_uin_hash = crypto
        .createHash('sha256')
        .update(fields.signer_nric.trim().toUpperCase())
        .digest('hex');
    }

    console.log("JWT payload:", JSON.stringify(jwtPayload));

    // Header has NO "typ" field — matching the docs example exactly
    const header    = { alg: 'ES256', kid };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const bodyB64   = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
    const message   = `${headerB64}.${bodyB64}`;

    const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
    const signature  = crypto.sign('sha256', Buffer.from(message), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    const token = `${message}.${signature.toString('base64url')}`;
    console.log("JWT created ✓, posting to:", apiUrl);

    // ── POST raw PDF bytes to Singpass ─────────────────────────────────────────
    // Content-Type: application/octet-stream
    // Body: raw PDF bytes
    const result = await new Promise((resolve, reject) => {
      const url     = new URL(apiUrl);
      const options = {
        hostname: url.hostname,
        port:     443,
        path:     url.pathname,
        method:   'POST',
        headers:  {
          'Authorization':  `Bearer ${token}`,
          'Content-Type':   'application/octet-stream',
          'Content-Length': pdfFile.length,
        },
        timeout: 20000,
      };

      const request = https.request(options, (response) => {
        const chunks = [];
        response.on('data', c => chunks.push(c));
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString();
          console.log("Singpass status:", response.statusCode);
          console.log("Singpass body:",   body.substring(0, 500));
          resolve({ status: response.statusCode, body });
        });
      });

      request.on('error',   reject);
      request.on('timeout', () => { request.destroy(); reject(new Error('Request timed out')); });
      request.write(pdfFile);
      request.end();
    });

    if (result.status === 200 || result.status === 201) {
      let data;
      try { data = JSON.parse(result.body); }
      catch (e) {
        return res.status(502).json({ error: "Invalid JSON from Singpass", body: result.body.substring(0, 300) });
      }

      if (!data.request_id || !data.signing_url) {
        return res.status(502).json({
          error:    "Incomplete response from Singpass",
          expected: ["request_id", "signing_url", "exchange_code"],
          received: Object.keys(data),
          data,
        });
      }

      return res.status(200).json({
        sign_request_id: data.request_id,
        signing_url:     data.signing_url,
        exchange_code:   data.exchange_code,
      });
    }

    let detail = result.body;
    try { detail = JSON.parse(result.body); } catch (_) {}
    return res.status(502).json({
      error:  `Singpass API returned ${result.status}`,
      status: result.status,
      detail,
      url: apiUrl,
    });

  } catch (error) {
    console.error("Fatal error:", error.message, error.code);
    return res.status(500).json({
      error:   "Internal server error",
      message: error.message,
      code:    error.code,
    });
  }
};

module.exports.config = { api: { bodyParser: false } };
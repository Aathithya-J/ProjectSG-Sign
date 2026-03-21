/**
 * POST /api/webhook/singpass
 *
 * Receives Singpass signing-completion callbacks.
 * When a document is successfully signed this handler:
 *   1. Downloads the signed PDF from Singpass.
 *   2. Emails it as an attachment to info@project.sg via SMTP (Nodemailer).
 *
 * Required environment variables (set in Vercel / hosting dashboard):
 *   SMTP_HOST     – e.g. smtp.mailgun.org
 *   SMTP_PORT     – e.g. 587
 *   SMTP_USER     – SMTP username / API key
 *   SMTP_PASS     – SMTP password / API secret
 *   SMTP_FROM     – Sender address, e.g. noreply@project.sg
 *                   (defaults to SMTP_USER if not set)
 *
 * The webhook payload from Singpass contains at minimum:
 *   { "request_id": "...", "exchange_code": "...", "status": "SIGNED" | ... }
 */

const crypto = require("crypto");
const https = require("https");
const nodemailer = require("nodemailer");

// ---------------------------------------------------------------------------
// Helpers (shared JWT / signing logic)
// ---------------------------------------------------------------------------

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function createJWT(payload, privateKey, kid, aud) {
  const header = { alg: "ES256", typ: "JWT", kid };
  const iat = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat,
    exp: iat + 120,
    jti: crypto.randomUUID(),
    aud,
    iss: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4",
    sub: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4",
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign("SHA256");
  signer.update(signatureInput);
  const signature = signer
    .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${signatureInput}.${signature}`;
}

// ---------------------------------------------------------------------------
// Download the signed PDF from Singpass
// ---------------------------------------------------------------------------

function fetchSignedDoc(requestId, exchangeCode) {
  return new Promise((resolve, reject) => {
    const clientId = "WTYhkYnUJubcEOzDokeJO4szhblsEzF4";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = `https://staging.sign.singpass.gov.sg/api/v3/sign-requests/${requestId}/signed-doc`;
    const jwt = createJWT({ client_id: clientId, exchange_code: exchangeCode }, privateKey, kid, apiUrl);

    const req = https.request(apiUrl, { method: "GET", headers: { Authorization: jwt, Accept: "application/json" } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`Singpass API returned ${res.statusCode}: ${data}`));
        }
        let result;
        try { result = JSON.parse(data); } catch (e) { return reject(new Error("Failed to parse Singpass response")); }
        if (!result.signed_doc_url) return reject(new Error("No signed_doc_url in response"));
        resolve(result.signed_doc_url);
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function downloadPdfFromUrl(pdfUrl) {
  return new Promise((resolve, reject) => {
    https.get(pdfUrl, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`Failed to download PDF: HTTP ${res.statusCode}`));
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Send email with the signed PDF attached
// ---------------------------------------------------------------------------

async function emailSignedDocument(pdfBuffer, requestId) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: parseInt(process.env.SMTP_PORT || "587", 10) === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const filename = `signed_document_${requestId}.pdf`;

  await transporter.sendMail({
    from,
    to: "info@project.sg",
    subject: `Signed Document – Request ${requestId}`,
    text: `A document has been signed via Singpass.\n\nSign Request ID: ${requestId}\n\nPlease find the signed PDF attached.`,
    html: `
      <p>A document has been signed via <strong>Singpass</strong>.</p>
      <p><strong>Sign Request ID:</strong> ${requestId}</p>
      <p>Please find the signed PDF attached.</p>
    `,
    attachments: [
      {
        filename,
        content: pdfBuffer,
        contentType: "application/pdf",
      },
    ],
  });

  console.log(`[webhook] Signed document emailed to info@project.sg (request: ${requestId})`);
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  try {
    // Parse body (Vercel parses JSON automatically when bodyParser is enabled)
    const body = req.body || {};
    console.log("[webhook] Singpass payload received:", JSON.stringify(body, null, 2));

    const { request_id, exchange_code, status } = body;

    // Acknowledge immediately so Singpass does not retry
    res.status(200).send("OK");

    // Only process completed signings
    if (status !== "SIGNED" && status !== "signed") {
      console.log(`[webhook] Ignoring non-signed status: ${status}`);
      return;
    }

    if (!request_id || !exchange_code) {
      console.error("[webhook] Missing request_id or exchange_code in payload");
      return;
    }

    // Retrieve and email the signed document asynchronously
    (async () => {
      try {
        console.log(`[webhook] Fetching signed doc for request: ${request_id}`);
        const signedDocUrl = await fetchSignedDoc(request_id, exchange_code);
        const pdfBuffer = await downloadPdfFromUrl(signedDocUrl);
        await emailSignedDocument(pdfBuffer, request_id);
      } catch (err) {
        console.error("[webhook] Failed to process signed document:", err.message);
      }
    })();
  } catch (err) {
    console.error("[webhook] Unexpected error:", err.message);
    if (!res.headersSent) res.status(500).send("Internal Server Error");
  }
};

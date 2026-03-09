import crypto from "crypto";
import { IncomingForm } from "formidable";
import { readFileSync } from "fs";

const STAGING_API   = "https://stg-api.sign.singpass.gov.sg";
const PROD_API      = "https://api.sign.singpass.gov.sg";
const SIGN_ENDPOINT = "/v3/signing-sessions";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeJwt(payload, pemKey, kid) {
  const header  = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
  const body    = b64url(JSON.stringify(payload));
  const message = `${header}.${body}`;
  const sig     = crypto.createSign("RSA-SHA256").update(message).sign(pemKey);
  return `${message}.${b64url(sig)}`;
}

function authToken(clientId, pem, kid, audience) {
  const now = Math.floor(Date.now() / 1000);
  return makeJwt(
    { sub: clientId, iss: clientId, aud: audience,
      iat: now, exp: now + 300, jti: crypto.randomUUID() },
    pem, kid
  );
}

export const config = {
  api: { bodyParser: false },
  runtime: "nodejs20.x",
};

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method not allowed" });

  const clientId    = process.env.SINGPASS_CLIENT_ID    || "";
  const pem         = (process.env.SINGPASS_PRIVATE_KEY_PEM || "").replace(/\\n/g, "\n");
  const kid         = process.env.SINGPASS_KID           || "";
  const webhookBase = process.env.WEBHOOK_BASE_URL       || "";

  if (!clientId || !pem || !kid) {
    const missing = ["SINGPASS_CLIENT_ID","SINGPASS_PRIVATE_KEY_PEM","SINGPASS_KID"]
      .filter(k => !process.env[k]);
    return res.status(500).json({ error: "Missing env vars", missing });
  }

  // Parse multipart form
  let fields, files;
  try {
    [fields, files] = await new Promise((resolve, reject) => {
      const form = new IncomingForm({ maxFileSize: 10 * 1024 * 1024 });
      form.parse(req, (err, f, fi) => err ? reject(err) : resolve([f, fi]));
    });
  } catch (e) {
    return res.status(400).json({ error: `Form parse error: ${e.message}` });
  }

  const fileEntry = files?.file?.[0] || files?.file;
  if (!fileEntry) return res.status(400).json({ error: "No PDF provided" });

  const pdfBytes  = readFileSync(fileEntry.filepath);
  const isStaging = (fields?.staging?.[0] ?? fields?.staging ?? "1") === "1";
  const docName   = fields?.doc_name?.[0]    || fields?.doc_name    || fileEntry.originalFilename || "document.pdf";
  const signerNric= (fields?.signer_nric?.[0]|| fields?.signer_nric || "").trim().toUpperCase();
  const apiBase   = isStaging ? STAGING_API : PROD_API;

  const spPayload = {
    doc_name: docName,
    sign_locations: Array.from({ length: 20 }, (_, i) => ({
      page: i + 1, x: 0.72, y: 0.05, width: 0.25, height: 0.06,
    })),
  };
  if (signerNric)  spPayload.signer_uin_hash = crypto.createHash("sha256").update(signerNric).digest("hex");
  if (webhookBase) spPayload.webhook_url     = webhookBase.replace(/\/$/, "") + "/api/webhook/singpass";

  const url   = apiBase + SIGN_ENDPOINT;
  const token = authToken(clientId, pem, kid, url);

  // Build multipart body
  const boundary = crypto.randomUUID().replace(/-/g, "");
  const CRLF     = "\r\n";
  const bodyParts = Buffer.concat([
    Buffer.from(
      `--${boundary}${CRLF}` +
      `Content-Disposition: form-data; name="payload"${CRLF}` +
      `Content-Type: application/json${CRLF}${CRLF}` +
      JSON.stringify(spPayload) + CRLF +
      `--${boundary}${CRLF}` +
      `Content-Disposition: form-data; name="file"; filename="${docName}"${CRLF}` +
      `Content-Type: application/pdf${CRLF}${CRLF}`
    ),
    pdfBytes,
    Buffer.from(`${CRLF}--${boundary}--${CRLF}`),
  ]);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization":  `Bearer ${token}`,
        "Content-Type":   `multipart/form-data; boundary=${boundary}`,
        "Content-Length": String(bodyParts.length),
      },
      body: bodyParts,
    });

    const text = await response.text();
    if (!response.ok) {
      return res.status(502).json({ error: `Singpass API ${response.status}`, detail: text });
    }

    const data = JSON.parse(text);
    return res.status(200).json({
      sign_request_id: data.sign_request_id || "",
      signing_url:     data.signing_url     || "",
    });

  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
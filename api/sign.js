import crypto from "crypto";

const STAGING_URL = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL    = "https://sign.singpass.gov.sg/api/v3/sign-requests";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeJwt(payload, pem, kid) {
  const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
  const body   = b64url(JSON.stringify(payload));
  const msg    = `${header}.${body}`;
  const keyObj = crypto.createPrivateKey({ key: pem, format: "pem" });
  const sig    = crypto.sign("SHA256", Buffer.from(msg), { key: keyObj, dsaEncoding: "ieee-p1363" });
  return `${msg}.${b64url(sig)}`;
}

function authToken(clientId, pem, kid, docName, signLocations, signerUinHash) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    client_id:      clientId,
    doc_name:       docName,
    sign_locations: signLocations,
    iat:            now,
    exp:            now + 110,   // must be within 2 minutes
    jti:            crypto.randomUUID(),
  };
  if (signerUinHash) payload.signer_uin_hash = signerUinHash;
  return makeJwt(payload, pem, kid);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end",  () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseMultipart(buf, contentType) {
  const match = contentType.match(/boundary=(.+)/);
  if (!match) return { fields: {}, file: null, filename: "document.pdf" };
  const boundary = Buffer.from("--" + match[1].trim());
  const fields = {};
  let file = null, filename = "document.pdf";
  let pos = 0;
  while (pos < buf.length) {
    const bPos = buf.indexOf(boundary, pos);
    if (bPos === -1) break;
    pos = bPos + boundary.length;
    if (buf[pos] === 0x2d && buf[pos+1] === 0x2d) break;
    if (buf[pos] === 0x0d) pos += 2;
    const hEnd = buf.indexOf(Buffer.from("\r\n\r\n"), pos);
    if (hEnd === -1) break;
    const headers = buf.slice(pos, hEnd).toString();
    pos = hEnd + 4;
    const next = buf.indexOf(boundary, pos);
    const content = buf.slice(pos, next === -1 ? buf.length : next - 2);
    pos = next === -1 ? buf.length : next;
    const nameMatch     = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    if (name === "file" && filenameMatch) { file = content; filename = filenameMatch[1]; }
    else fields[name] = content.toString().trim();
  }
  return { fields, file, filename };
}

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")   return res.status(405).json({ error: "Method not allowed" });

  const clientId    = process.env.SINGPASS_CLIENT_ID            || "";
  const pem = (process.env.SINGPASS_PRIVATE_KEY_PEM || "")
    .replace(/\\n/g, "\n")
    .replace(/\n\n/g, "\n")
    .trim();
  const kid         = process.env.SINGPASS_KID                  || "";
  const webhookBase = process.env.WEBHOOK_BASE_URL              || "";

  if (!clientId || !pem || !kid) {
    const missing = ["SINGPASS_CLIENT_ID","SINGPASS_PRIVATE_KEY_PEM","SINGPASS_KID"].filter(k => !process.env[k]);
    return res.status(500).json({ error: "Missing env vars", missing });
  }

  // Debug: verify PEM looks correct
  const pemOk = pem.includes("-----BEGIN PRIVATE KEY-----") && pem.includes("-----END PRIVATE KEY-----");
  if (!pemOk) {
    return res.status(500).json({ 
      error: "Invalid PEM format", 
      preview: pem.slice(0, 80),
      hint: "PEM must start with -----BEGIN PRIVATE KEY----- on its own line"
    });
  }

  const rawBody = await readBody(req);
  const { fields, file, filename } = parseMultipart(rawBody, req.headers["content-type"] || "");
  if (!file) return res.status(400).json({ error: "No PDF provided" });

  const isStaging   = (fields.staging ?? "1") === "1";
  const docName     = fields.doc_name || filename || "document.pdf";
  const signerNric  = (fields.signer_nric || "").trim().toUpperCase();
  const signerHash  = signerNric ? crypto.createHash("sha256").update(signerNric).digest("hex") : null;
  const apiUrl      = isStaging ? STAGING_URL : PROD_URL;

  // Sign locations go in the JWT, not the body
  const signLocations = Array.from({ length: 20 }, (_, i) => ({
    page: i + 1, x: 0.72, y: 0.05,
  }));

  const token = authToken(clientId, pem, kid, docName, signLocations, signerHash);

  try {
    // Body is raw PDF bytes, Content-Type is application/octet-stream
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type":  "application/octet-stream",
      },
      body: file,
    });

    const text = await response.text();
    if (!response.ok) {
      return res.status(502).json({ error: `Singpass API ${response.status}`, detail: text });
    }

    const data = JSON.parse(text);
    return res.status(200).json({
      sign_request_id: data.request_id    || "",   // API returns request_id
      signing_url:     data.signing_url   || "",
      exchange_code:   data.exchange_code || "",
    });

  } catch (e) {
    return res.status(500).json({ 
      error: e.message, 
      cause: String(e.cause || ""),
      stack: e.stack?.split("\n").slice(0,3).join(" | ")
    });
  }
}
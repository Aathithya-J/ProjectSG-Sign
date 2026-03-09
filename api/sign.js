const crypto = require("crypto");

// Correct API endpoints from documentation
const STAGING_URL = "https://stg.api.sign.singpass.gov.sg/v3/signing-sessions";
const PROD_URL    = "https://api.sign.singpass.gov.sg/v3/signing-sessions";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeJwt(payload, pem, kid) {
  const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
  const body   = b64url(JSON.stringify(payload));
  const msg    = `${header}.${body}`;
  const keyObj = crypto.createPrivateKey(pem);
  const sig    = crypto.sign("SHA256", Buffer.from(msg), { 
    key: keyObj, 
    dsaEncoding: "ieee-p1363" 
  });
  return `${msg}.${b64url(sig)}`;
}

function authToken(clientId, pem, kid, docName, signLocations, signerUinHash, webhookBase) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    client_id: clientId,
    doc_name: docName,
    sign_locations: signLocations,
    // Required fields from documentation
    iat: now,
    exp: now + 300, // 5 minutes expiry (documentation recommends 5 min)
    jti: crypto.randomUUID(),
    // Include webhook URL
    webhook_url: `${webhookBase}/api/webhook/singpass`
  };
  
  // Only include if provided (optional)
  if (signerUinHash) {
    payload.signer_uin_hash = signerUinHash;
  }
  
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
    
    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    
    if (!nameMatch) continue;
    
    const name = nameMatch[1];
    if (name === "file" && filenameMatch) { 
      file = content; 
      filename = filenameMatch[1]; 
    } else if (name) {
      fields[name] = content.toString().trim();
    }
  }
  
  return { fields, file, filename };
}

module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const clientId = process.env.SINGPASS_CLIENT_ID || "";
    const pem = (process.env.SINGPASS_PRIVATE_KEY_PEM || "").replace(/\\n/g, "\n");
    const kid = process.env.SINGPASS_KID || "";
    const webhookBase = process.env.WEBHOOK_BASE_URL || "";

    if (!clientId || !pem || !kid) {
      const missing = ["SINGPASS_CLIENT_ID","SINGPASS_PRIVATE_KEY_PEM","SINGPASS_KID"].filter(k => !process.env[k]);
      return res.status(500).json({ error: "Missing env vars", missing });
    }

    if (!webhookBase) {
      return res.status(500).json({ error: "Missing WEBHOOK_BASE_URL env var" });
    }

    const rawBody = await readBody(req);
    const { fields, file, filename } = parseMultipart(rawBody, req.headers["content-type"] || "");
    
    if (!file) {
      return res.status(400).json({ error: "No PDF provided" });
    }

    const isStaging = (fields.staging ?? "1") === "1";
    const docName = fields.doc_name || filename || "document.pdf";
    const signerNric = (fields.signer_nric || "").trim().toUpperCase();
    const signerHash = signerNric ? crypto.createHash("sha256").update(signerNric).digest("hex") : null;
    const apiUrl = isStaging ? STAGING_URL : PROD_URL;

    // Fix signature placement - using correct format from documentation
    // Place signature at bottom right of first page
    const signLocations = [
      {
        page: 1,
        x: 0.72,  // 72% from left (bottom right)
        y: 0.05,  // 5% from bottom
        width: 150,  // Optional: signature width in pixels
        height: 50   // Optional: signature height in pixels
      }
    ];
    
    // If you want multiple signatures, add more locations (max 20)
    // signLocations.push({ page: 2, x: 0.72, y: 0.05 });

    const token = authToken(clientId, pem, kid, docName, signLocations, signerHash, webhookBase);

    console.log("Calling Singpass API:", apiUrl);
    console.log("Document name:", docName);
    console.log("Staging:", isStaging);

    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/pdf",  // Changed from application/octet-stream
      },
      body: file,
    });

    const text = await response.text();
    console.log("Singpass API response status:", response.status);
    console.log("Singpass API response body:", text);

    if (!response.ok) {
      return res.status(502).json({ 
        error: `Singpass API ${response.status}`, 
        detail: text,
        requestId: response.headers.get("x-request-id") || "unknown"
      });
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return res.status(502).json({ 
        error: "Invalid JSON response from Singpass", 
        detail: text 
      });
    }

    // Store in memory for webhook to update (replace with proper DB in production)
    if (data.request_id) {
      // You'll need to implement proper storage
      // This is just a placeholder
      if (!global._signStore) global._signStore = {};
      global._signStore[data.request_id] = {
        exchange_code: data.exchange_code,
        status: "pending",
        created_at: Date.now()
      };
    }

    return res.status(200).json({
      sign_request_id: data.request_id || "",
      signing_url: data.signing_url || "",
      exchange_code: data.exchange_code || "",
    });

  } catch (e) {
    console.error("Error in sign handler:", e);
    return res.status(500).json({
      error: e.message,
      stack: process.env.NODE_ENV === "development" ? e.stack : undefined
    });
  }
};

module.exports.config = { 
  api: { 
    bodyParser: false,
    externalResolver: true
  } 
};
const crypto = require("crypto");
const https = require("https");

// Correct API endpoints from documentation
const STAGING_URL = "https://stg.api.sign.singpass.gov.sg/v3/signing-sessions";
const PROD_URL = "https://api.sign.singpass.gov.sg/v3/signing-sessions";

// Alternative endpoints if the above don't work
const STAGING_URL_ALT = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL_ALT = "https://sign.singpass.gov.sg/api/v3/sign-requests";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeJwt(payload, pem, kid) {
  try {
    const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
    const body = b64url(JSON.stringify(payload));
    const msg = `${header}.${body}`;
    
    // Log JWT parts for debugging (without sensitive data)
    console.log("JWT header:", JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
    console.log("JWT payload keys:", Object.keys(payload));
    
    const keyObj = crypto.createPrivateKey({
      key: pem,
      format: 'pem',
      type: 'pkcs8'
    });
    
    const sig = crypto.sign("SHA256", Buffer.from(msg), { 
      key: keyObj, 
      dsaEncoding: "ieee-p1363" 
    });
    
    return `${msg}.${b64url(sig)}`;
  } catch (error) {
    console.error("JWT creation error:", error);
    throw new Error(`Failed to create JWT: ${error.message}`);
  }
}

function authToken(clientId, pem, kid, docName, signLocations, signerUinHash, webhookBase) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    client_id: clientId,
    doc_name: docName,
    sign_locations: signLocations,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
    webhook_url: `${webhookBase}/api/webhook/singpass`
  };
  
  if (signerUinHash) {
    payload.signer_uin_hash = signerUinHash;
  }
  
  return makeJwt(payload, pem, kid);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
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

// Function to test endpoint connectivity
async function testEndpoint(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(url, {
      method: "HEAD",
      signal: controller.signal
    }).catch(() => null);
    
    clearTimeout(timeoutId);
    return response !== null;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const clientId = process.env.SINGPASS_CLIENT_ID || "";
    const pem = (process.env.SINGPASS_PRIVATE_KEY_PEM || "").replace(/\\n/g, "\n");
    const kid = process.env.SINGPASS_KID || "";
    const webhookBase = process.env.WEBHOOK_BASE_URL || "";

    // Log environment (without sensitive data)
    console.log("Environment check:", {
      hasClientId: !!clientId,
      hasPem: !!pem,
      hasKid: !!kid,
      hasWebhookBase: !!webhookBase,
      webhookBase: webhookBase
    });

    if (!clientId || !pem || !kid) {
      const missing = ["SINGPASS_CLIENT_ID", "SINGPASS_PRIVATE_KEY_PEM", "SINGPASS_KID"]
        .filter(k => !process.env[k]);
      return res.status(500).json({ 
        error: "Missing environment variables", 
        missing,
        note: "Please set these in Vercel dashboard"
      });
    }

    if (!webhookBase) {
      return res.status(500).json({ 
        error: "Missing WEBHOOK_BASE_URL env var",
        note: "Set this to your Vercel deployment URL (e.g., https://your-app.vercel.app)"
      });
    }

    // Parse request
    const rawBody = await readBody(req);
    const contentType = req.headers["content-type"] || "";
    
    console.log("Content-Type:", contentType);
    console.log("Body size:", rawBody.length);
    
    const { fields, file, filename } = parseMultipart(rawBody, contentType);
    
    if (!file) {
      return res.status(400).json({ error: "No PDF file provided" });
    }

    console.log("PDF size:", file.length);
    console.log("Filename:", filename);
    console.log("Fields:", Object.keys(fields));

    const isStaging = fields.staging !== "0"; // Default to staging
    const docName = fields.doc_name || filename || "document.pdf";
    const signerNric = (fields.signer_nric || "").trim().toUpperCase();
    const signerHash = signerNric ? crypto.createHash("sha256").update(signerNric).digest("hex") : null;

    // Try primary endpoint first
    const primaryUrl = isStaging ? STAGING_URL : PROD_URL;
    const altUrl = isStaging ? STAGING_URL_ALT : PROD_URL_ALT;
    
    console.log("Attempting primary URL:", primaryUrl);
    
    // Signature placement
    const signLocations = [
      {
        page: 1,
        x: 0.72,
        y: 0.05,
      }
    ];

    // Create JWT token
    let token;
    try {
      token = authToken(clientId, pem, kid, docName, signLocations, signerHash, webhookBase);
      console.log("JWT created successfully");
    } catch (jwtError) {
      console.error("JWT creation failed:", jwtError);
      return res.status(500).json({ 
        error: "Failed to create JWT token", 
        detail: jwtError.message,
        note: "Check your private key format"
      });
    }

    // Try primary endpoint with fetch
    let response;
    let usedUrl = primaryUrl;
    let error;
    
    try {
      // Use node-fetch with custom agent for better compatibility
      const fetch = require('node-fetch');
      const https = require('https');
      
      const agent = new https.Agent({
        rejectUnauthorized: true, // Set to false for testing only
        keepAlive: true
      });
      
      response = await fetch(primaryUrl, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/pdf",
          "User-Agent": "Singpass-Sign-App/1.0"
        },
        body: file,
        agent,
        timeout: 30000 // 30 second timeout
      });
      
      console.log("Primary endpoint response status:", response.status);
    } catch (fetchError) {
      console.error("Primary endpoint failed:", fetchError.message);
      error = fetchError;
      
      // Try alternative endpoint
      console.log("Trying alternative endpoint:", altUrl);
      try {
        const fetch = require('node-fetch');
        const https = require('https');
        
        const agent = new https.Agent({
          rejectUnauthorized: true,
          keepAlive: true
        });
        
        response = await fetch(altUrl, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/pdf",
            "User-Agent": "Singpass-Sign-App/1.0"
          },
          body: file,
          agent,
          timeout: 30000
        });
        
        usedUrl = altUrl;
        console.log("Alternative endpoint response status:", response.status);
      } catch (altError) {
        console.error("Both endpoints failed");
        return res.status(502).json({ 
          error: "Failed to connect to Singpass API",
          primary: {
            url: primaryUrl,
            error: fetchError.message
          },
          alternative: {
            url: altUrl,
            error: altError.message
          },
          note: "Check if your Vercel deployment can access external APIs"
        });
      }
    }

    // Get response text
    const text = await response.text();
    console.log("Response status:", response.status);
    console.log("Response headers:", Object.fromEntries(response.headers));
    console.log("Response body:", text.substring(0, 500)); // First 500 chars

    if (!response.ok) {
      return res.status(502).json({ 
        error: `Singpass API returned ${response.status}`,
        url: usedUrl,
        status: response.status,
        statusText: response.statusText,
        detail: text,
        requestId: response.headers.get("x-request-id") || "unknown"
      });
    }

    // Parse JSON response
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return res.status(502).json({ 
        error: "Invalid JSON response from Singpass", 
        detail: text.substring(0, 200),
        url: usedUrl
      });
    }

    // Validate response has required fields
    if (!data.request_id || !data.signing_url) {
      return res.status(502).json({ 
        error: "Incomplete response from Singpass",
        received: Object.keys(data),
        expected: ["request_id", "signing_url", "exchange_code"],
        data: data
      });
    }

    return res.status(200).json({
      sign_request_id: data.request_id,
      signing_url: data.signing_url,
      exchange_code: data.exchange_code,
    });

  } catch (e) {
    console.error("Unhandled error in sign handler:", e);
    return res.status(500).json({
      error: "Internal server error",
      message: e.message,
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
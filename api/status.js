const crypto = require("crypto");

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

function authToken(clientId, pem, kid, audience) {
  const now = Math.floor(Date.now() / 1000);
  return makeJwt({
    sub: clientId, 
    iss: clientId, 
    aud: audience,
    iat: now, 
    exp: now + 110, 
    jti: crypto.randomUUID(),
  }, pem, kid);
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { id: reqId, exchange_code: exchangeCode, staging } = req.query;
    const isStaging = (staging ?? "1") === "1";

    if (!reqId || !exchangeCode) {
      return res.status(400).json({ error: "Missing id or exchange_code" });
    }

    const clientId = process.env.SINGPASS_CLIENT_ID || "";
    const pem = (process.env.SINGPASS_PRIVATE_KEY_PEM || "").replace(/\\n/g, "\n");
    const kid = process.env.SINGPASS_KID || "";
    const apiBase = isStaging ? STAGING_URL : PROD_URL;

    if (!clientId || !pem || !kid) {
      return res.status(500).json({ error: "Missing env vars" });
    }

    const resultUrl = `${apiBase}/${reqId}/result`;
    console.log("Status check URL:", resultUrl);
    
    const token = authToken(clientId, pem, kid, resultUrl);

    const response = await fetch(resultUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ exchange_code: exchangeCode }),
    });

    const text = await response.text();
    console.log("Status API response status:", response.status);
    console.log("Status API response body:", text);

    if (!response.ok) {
      return res.status(response.status).json({ 
        error: `Singpass API ${response.status}`,
        detail: text 
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

    // Check for signed document URL
    if (data.download_url || data.signed_doc_url) {
      return res.status(200).json({
        status: "signed",
        signed_doc_url: data.download_url || data.signed_doc_url,
        signed_at: data.signed_at || null
      });
    }

    return res.status(200).json({ 
      status: "pending" 
    });

  } catch (e) {
    console.error("Error in status handler:", e);
    return res.status(500).json({ 
      status: "error", 
      error: e.message 
    });
  }
};
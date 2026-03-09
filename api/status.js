const crypto = require("crypto");

const STAGING_URL = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL    = "https://sign.singpass.gov.sg/api/v3/sign-requests";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeJwt(payload, pem, kid) {
  const header = b64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
  const body   = b64url(JSON.stringify(payload));
  const msg    = `${header}.${body}`;
  const keyObj = crypto.createPrivateKey(pem);
  const sig    = crypto.sign("SHA256", Buffer.from(msg), { key: keyObj, dsaEncoding: "ieee-p1363" });
  return `${msg}.${b64url(sig)}`;
}

function authToken(clientId, pem, kid, audience) {
  const now = Math.floor(Date.now() / 1000);
  return makeJwt({
    sub: clientId, iss: clientId, aud: audience,
    iat: now, exp: now + 110, jti: crypto.randomUUID(),
  }, pem, kid);
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") return res.status(204).end();

  try {
    const { id: reqId, exchange_code: exchangeCode, staging } = req.query;
    const isStaging = (staging ?? "1") === "1";

    if (!reqId || !exchangeCode) {
      return res.status(400).json({ error: "Missing id or exchange_code" });
    }

    const clientId = process.env.SINGPASS_CLIENT_ID || "";
    const pem    = process.env.SINGPASS_PRIVATE_KEY_PEM || "";
    const kid      = process.env.SINGPASS_KID || "";
    const apiBase  = isStaging ? STAGING_URL : PROD_URL;

    const resultUrl = `${apiBase}/${reqId}/result`;
    const token     = authToken(clientId, pem, kid, resultUrl);

    const response = await fetch(resultUrl, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type":  "application/json",
      },
      body: JSON.stringify({ exchange_code: exchangeCode }),
    });

    const text = await response.text();
    const data = JSON.parse(text);

    if (data.signed_doc_url || data.download_url) {
      return res.status(200).json({
        status: "signed",
        signed_doc_url: data.signed_doc_url || data.download_url,
      });
    }

    return res.status(200).json({ status: "pending" });

  } catch (e) {
    return res.status(200).json({ status: "pending", debug: e.message });
  }
};
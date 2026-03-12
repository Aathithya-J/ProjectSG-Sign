// api/status.js
const crypto = require('crypto');

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildJwt({ clientId, kid, privateKeyPem, signRequestId }) {
  const header = base64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid })));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(Buffer.from(JSON.stringify({
    client_id: clientId,
    sign_request_id: signRequestId,
    iat: now,
    jti: crypto.randomUUID(),
  })));
  const signingInput = `${header}.${payload}`;
  const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });
  const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${base64url(sigBuf)}`;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { sign_request_id } = req.query;
  if (!sign_request_id) return res.status(400).json({ error: 'Missing sign_request_id' });

  try {
    const clientId = process.env.SINGPASS_CLIENT_ID;
    const kid = process.env.SINGPASS_KID;
    const rawPem = process.env.SINGPASS_PRIVATE_KEY_PEM;

    if (!clientId || !kid || !rawPem) {
      return res.status(500).json({ error: 'Missing env vars' });
    }

    const privateKeyPem = rawPem.replace(/\\n/g, '\n');
    const jwt = buildJwt({ clientId, kid, privateKeyPem, signRequestId: sign_request_id });

    const singpassRes = await fetch(
      `https://staging.sign.singpass.gov.sg/api/v3/sign-requests/${encodeURIComponent(sign_request_id)}`,
      { method: 'GET', headers: { Authorization: `Bearer ${jwt}` } }
    );

    if (!singpassRes.ok) {
      const errText = await singpassRes.text();
      return res.status(502).json({ error: 'Singpass error', status: singpassRes.status, detail: errText });
    }

    const data = await singpassRes.json();
    return res.status(200).json({ status: data.status, signed_doc_url: data.signed_doc_url ?? null });

  } catch (err) {
    console.error('status.js error:', err);
    return res.status(500).json({ error: err.message });
  }
};
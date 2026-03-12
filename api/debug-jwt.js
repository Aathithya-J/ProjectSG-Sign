// api/debug-jwt.js — TEMPORARY, delete after debugging
const crypto = require('crypto');

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

module.exports = async function handler(req, res) {
  const rawPem  = process.env.SINGPASS_PRIVATE_KEY_PEM;
  const clientId = process.env.SINGPASS_CLIENT_ID;
  const kid      = process.env.SINGPASS_KID;
  const pem      = rawPem.replace(/\\n/g, '\n');

  // Build the exact JWT sign.js would send
  const privKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
  const header  = base64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid })));
  const payload = base64url(Buffer.from(JSON.stringify({
    client_id: clientId,
    doc_name: 'test.pdf',
    x: 0.5, y: 0.1, page: 1,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  })));
  const signingInput = `${header}.${payload}`;
  const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privKey, dsaEncoding: 'ieee-p1363',
  });
  const jwt = `${signingInput}.${base64url(sigBuf)}`;

  // Fetch what Singpass staging sees at your JWKS URL
  const jwksUrl = 'https://project-sg-sign.vercel.app/api/jwks';
  let jwksResult;
  try {
    const r = await fetch(jwksUrl);
    jwksResult = { status: r.status, body: await r.json() };
  } catch(e) {
    jwksResult = { error: e.message };
  }

  // Try hitting Singpass with a tiny fake PDF to see the real error
  const fakePdf = Buffer.from('%PDF-1.4 test');
  let singpassResult;
  try {
    const r = await fetch('https://staging.sign.singpass.gov.sg/api/v3/sign-requests', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${jwt}`, 'Content-Type': 'application/octet-stream' },
      body: fakePdf,
    });
    singpassResult = { status: r.status, body: await r.text() };
  } catch(e) {
    singpassResult = { error: e.message };
  }

  return res.status(200).json({
    fullJwt: jwt,
    decodedHeader:  JSON.parse(Buffer.from(header,  'base64url').toString()),
    decodedPayload: JSON.parse(Buffer.from(payload, 'base64url').toString()),
    yourJwksUrl: jwksUrl,
    jwksResult,
    singpassResult,
  });
};
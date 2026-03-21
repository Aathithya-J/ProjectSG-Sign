const crypto = require('crypto');
const https = require('https');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function createJWT(payload, privateKey, kid) {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: kid
  };
  
  const iat = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: iat,
    exp: iat + 120, // Must be issued within 2 minutes
    jti: crypto.randomUUID()
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signatureInput);
  const signature = signer.sign(privateKey, 'base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `${signatureInput}.${signature}`;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { id, exchange_code } = req.query;
  if (!id || !exchange_code) {
    return res.status(400).json({ error: 'Missing sign_request_id or exchange_code' });
  }

  const kid = 'key-1';
  const privateKey = process.env.SINGPASS_PRIVATE_KEY_PEM;
  const apiUrl = `https://staging.sign.singpass.gov.sg/api/v3/sign-requests/${id}/signed-doc`;

  const jwt = createJWT({
    exchange_code: exchange_code
  }, privateKey, kid);

  const options = {
    method: 'GET',
    headers: {
      'Authorization': jwt,
      'Accept': 'application/json'
    }
  };

  const apiReq = https.request(apiUrl, options, (apiRes) => {
    let data = '';
    apiRes.on('data', (chunk) => data += chunk);
    apiRes.on('end', () => {
      try {
        if (apiRes.headers['content-type'] && apiRes.headers['content-type'].includes('application/json')) {
          const result = JSON.parse(data);
          if (apiRes.statusCode === 200) {
            res.status(200).json({ status: 'signed', signed_doc_url: result.signed_doc_url });
          } else if (apiRes.statusCode === 400 && result.error === 'DOCUMENT_NOT_SIGNED') {
            res.status(200).json({ status: 'pending' });
          } else {
            res.status(apiRes.statusCode).json(result);
          }
        } else {
          res.status(apiRes.statusCode).json({ error: 'API returned non-JSON response', raw: data });
        }
      } catch (e) {
        res.status(500).json({ error: 'Failed to parse API response', raw: data });
      }
    });
  });

  apiReq.on('error', (e) => {
    res.status(500).json({ error: e.message });
  });

  apiReq.end();
};

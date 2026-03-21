const crypto = require('crypto');
const https = require('https');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function createJWT(payload, privateKey, kid, aud) {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: kid
  };
  
  const iat = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: iat,
    exp: iat + 300,
    jti: crypto.randomBytes(16).toString('hex'),
    aud: aud
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

  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ error: 'Missing sign_request_id' });
  }

  const clientId = 'WTYhkYnUJubcEOzDokeJO4szhblsEzF4';
  const kid = 'key-1';
  const privateKey = process.env.SINGPASS_PRIVATE_KEY_PEM;
  const apiBase = 'https://staging.sign.singpass.gov.sg/api/v3';
  const apiUrl = `${apiBase}/signing-sessions/${id}/result`;

  const jwt = createJWT({
    sub: clientId,
    iss: clientId
  }, privateKey, kid, apiUrl);

  const options = {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${jwt}`,
      'Accept': 'application/json'
    }
  };

  const apiReq = https.request(apiUrl, options, (apiRes) => {
    let data = '';
    apiRes.on('data', (chunk) => data += chunk);
    apiRes.on('end', () => {
      try {
        const result = JSON.parse(data);
        if (apiRes.statusCode === 200) {
          if (result.status === 'signed') {
            res.status(200).json({ status: 'signed', signed_doc_url: result.signed_doc_url });
          } else {
            res.status(200).json({ status: 'pending' });
          }
        } else if (apiRes.statusCode === 202) {
          res.status(200).json({ status: 'pending' });
        } else {
          res.status(apiRes.statusCode).json(result);
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

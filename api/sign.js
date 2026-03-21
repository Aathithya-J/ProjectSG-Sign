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
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const contentType = req.headers['content-type'];
    const boundary = contentType.split('boundary=')[1];

    if (!boundary) {
      return res.status(400).json({ error: 'Invalid content type' });
    }

    const parts = body.toString('binary').split('--' + boundary);
    let pdfBuffer = null;
    let signerNric = null;
    let fileName = 'document.pdf';

    for (const part of parts) {
      if (part.includes('name="file"')) {
        const headerEnd = part.indexOf('\r\n\r\n');
        const content = part.substring(headerEnd + 4, part.lastIndexOf('\r\n'));
        pdfBuffer = Buffer.from(content, 'binary');
        const filenameMatch = part.match(/filename="([^"]+)"/);
        if (filenameMatch) fileName = filenameMatch[1];
      } else if (part.includes('name="signer_nric"')) {
        const headerEnd = part.indexOf('\r\n\r\n');
        signerNric = part.substring(headerEnd + 4, part.lastIndexOf('\r\n')).trim();
      }
    }

    if (!pdfBuffer) {
      return res.status(400).json({ error: 'No PDF file provided' });
    }

    const clientId = 'WTYhkYnUJubcEOzDokeJO4szhblsEzF4';
    const kid = 'key-1';
    const privateKey = process.env.SINGPASS_PRIVATE_KEY_PEM;
    const apiBase = 'https://staging.sign.singpass.gov.sg/api/v3';
    const apiUrl = `${apiBase}/signing-sessions`;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    const jwt = createJWT({
      sub: clientId,
      iss: clientId
    }, privateKey, kid, apiUrl);

    const signLocations = [];
    for (let i = 1; i <= 20; i++) {
      signLocations.push({
        page_index: i,
        x: 0.72,
        y: 0.05,
        width: 0.25,
        height: 0.06
      });
    }

    const payloadJson = {
      doc_name: fileName,
      sign_locations: signLocations
    };

    if (signerNric) {
      payloadJson.signer_uin_hash = crypto.createHash('sha256').update(signerNric).digest('hex');
    }

    if (webhookBase) {
      payloadJson.webhook_url = `${webhookBase}/api/webhook/singpass`;
    }

    const requestBoundary = '----ManusBoundary' + crypto.randomBytes(8).toString('hex');
    const header = `--${requestBoundary}\r\nContent-Disposition: form-data; name="payload"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(payloadJson)}\r\n--${requestBoundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: application/pdf\r\n\r\n`;
    const footer = `\r\n--${requestBoundary}--`;

    const requestBody = Buffer.concat([
      Buffer.from(header),
      pdfBuffer,
      Buffer.from(footer)
    ]);

    const options = {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${jwt}`,
        'Content-Type': `multipart/form-data; boundary=${requestBoundary}`,
        'Content-Length': requestBody.length
      }
    };

    const apiReq = https.request(apiUrl, options, (apiRes) => {
      let data = '';
      apiRes.on('data', (chunk) => data += chunk);
      apiRes.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (apiRes.statusCode >= 200 && apiRes.statusCode < 300) {
            res.status(200).json({
              sign_request_id: result.sign_request_id,
              signing_url: result.signing_url
            });
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

    apiReq.write(requestBody);
    apiReq.end();

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports.config = {
  api: {
    bodyParser: false
  }
};

// api/sign.js
const crypto = require('crypto');

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildJwt({ clientId, docName, x, y, page, privateKeyPem, kid }) {
  const header = base64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid })));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(Buffer.from(JSON.stringify({
    client_id: clientId,
    doc_name: docName,
    x, y, page,
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
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    // Read raw body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=([^\s;]+)/);
    if (!boundaryMatch) return res.status(400).json({ error: 'Missing multipart boundary' });
    const boundary = boundaryMatch[1];

    const pdfBuffer = extractFilePart(body, boundary);
    if (!pdfBuffer) return res.status(400).json({ error: 'No PDF file found in upload' });

    const fields = extractFormFields(body, boundary);
    const docName = fields.doc_name || 'document.pdf';
    const x = Number(fields.x ?? 0.5);
    const y = Number(fields.y ?? 0.1);
    const page = Number(fields.page ?? 1);

    const clientId = process.env.SINGPASS_CLIENT_ID;
    const kid = process.env.SINGPASS_KID;
    const rawPem = process.env.SINGPASS_PRIVATE_KEY_PEM;

    if (!clientId || !kid || !rawPem) {
      return res.status(500).json({ error: 'Missing env vars: SINGPASS_CLIENT_ID, SINGPASS_KID, or SINGPASS_PRIVATE_KEY_PEM' });
    }

    const privateKeyPem = rawPem.replace(/\\n/g, '\n');
    const jwt = buildJwt({ clientId, docName, x, y, page, privateKeyPem, kid });

    const singpassRes = await fetch('https://staging.sign.singpass.gov.sg/api/v3/sign-requests', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${jwt}`,
        'Content-Type': 'application/octet-stream',
      },
      body: pdfBuffer,
    });

    const responseText = await singpassRes.text();
    console.log('Singpass status:', singpassRes.status);
    console.log('Singpass response:', responseText);

    if (singpassRes.status !== 201 && singpassRes.status !== 200) {
      return res.status(502).json({
        error: 'Singpass API error',
        status: singpassRes.status,
        detail: responseText,
      });
    }

    const data = JSON.parse(responseText);
    return res.status(200).json({
      sign_request_id: data.sign_request_id,
      signing_url: data.signing_url,
      exchange_code: data.exchange_code,
    });

  } catch (err) {
    console.error('sign.js error:', err);
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
};

module.exports.config = { api: { bodyParser: false } };

function extractFilePart(body, boundary) {
  const boundaryBuf = Buffer.from(`--${boundary}`);
  let start = 0;
  while (start < body.length) {
    const boundaryIdx = body.indexOf(boundaryBuf, start);
    if (boundaryIdx === -1) break;
    const headerStart = boundaryIdx + boundaryBuf.length + 2;
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;
    const headerStr = body.slice(headerStart, headerEnd).toString('utf8');
    const nextBoundary = body.indexOf(boundaryBuf, headerEnd + 4);
    const partEnd = nextBoundary === -1 ? body.length : nextBoundary - 2;
    const partBody = body.slice(headerEnd + 4, partEnd);
    if (headerStr.includes('filename=') || headerStr.toLowerCase().includes('application/pdf')) {
      return partBody;
    }
    start = boundaryIdx + boundaryBuf.length;
  }
  return null;
}

function extractFormFields(body, boundary) {
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const fields = {};
  let start = 0;
  while (start < body.length) {
    const boundaryIdx = body.indexOf(boundaryBuf, start);
    if (boundaryIdx === -1) break;
    const headerStart = boundaryIdx + boundaryBuf.length + 2;
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;
    const headerStr = body.slice(headerStart, headerEnd).toString('utf8');
    const nextBoundary = body.indexOf(boundaryBuf, headerEnd + 4);
    const partEnd = nextBoundary === -1 ? body.length : nextBoundary - 2;
    const partBody = body.slice(headerEnd + 4, partEnd).toString('utf8').trim();
    if (!headerStr.includes('filename=')) {
      const nameMatch = headerStr.match(/name="([^"]+)"/);
      if (nameMatch) fields[nameMatch[1]] = partBody;
    }
    start = boundaryIdx + boundaryBuf.length;
  }
  return fields;
}
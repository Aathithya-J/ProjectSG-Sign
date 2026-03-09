const crypto = require('crypto');
const https = require('https');

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    // Log request details
    console.log("Request received:", {
      method: req.method,
      headers: req.headers,
      timestamp: new Date().toISOString()
    });

    // Check environment variables
    const clientId = process.env.SINGPASS_CLIENT_ID;
    const pem = (process.env.SINGPASS_PRIVATE_KEY_PEM || '').replace(/\\n/g, '\n');
    const kid = process.env.SINGPASS_KID;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    console.log("Environment check:", {
      clientId: clientId ? '✓' : '✗',
      pem: pem ? '✓' : '✗',
      kid: kid ? '✓' : '✗',
      webhookBase: webhookBase || '✗'
    });

    if (!clientId || !pem || !kid) {
      return res.status(500).json({
        error: "Missing required environment variables",
        missing: {
          clientId: !clientId,
          pem: !pem,
          kid: !kid
        }
      });
    }

    // Get the raw body
    const chunks = [];
    await new Promise((resolve, reject) => {
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', resolve);
      req.on('error', reject);
    });
    
    const rawBody = Buffer.concat(chunks);
    console.log("Body size:", rawBody.length);

    // Simple multipart parser
    const boundary = req.headers['content-type']?.split('boundary=')[1];
    if (!boundary) {
      return res.status(400).json({ error: "No boundary in content-type" });
    }

    const boundaryBuffer = Buffer.from(`--${boundary}`);
    const parts = [];
    let start = 0;
    
    while (start < rawBody.length) {
      const boundaryIndex = rawBody.indexOf(boundaryBuffer, start);
      if (boundaryIndex === -1) break;
      
      start = boundaryIndex + boundaryBuffer.length;
      
      // Skip if this is the last boundary
      if (rawBody[start] === 0x2d && rawBody[start + 1] === 0x2d) break;
      
      // Skip \r\n
      if (rawBody[start] === 0x0d) start += 2;
      
      // Find headers end
      const headerEnd = rawBody.indexOf(Buffer.from('\r\n\r\n'), start);
      if (headerEnd === -1) break;
      
      const headers = rawBody.slice(start, headerEnd).toString();
      start = headerEnd + 4;
      
      // Find next boundary
      const nextBoundary = rawBody.indexOf(boundaryBuffer, start);
      const content = rawBody.slice(start, nextBoundary !== -1 ? nextBoundary - 2 : undefined);
      
      parts.push({ headers, content });
      start = nextBoundary !== -1 ? nextBoundary : rawBody.length;
    }

    // Extract file and fields
    let pdfFile = null;
    const fields = {};
    
    for (const part of parts) {
      const nameMatch = part.headers.match(/name="([^"]+)"/);
      const filenameMatch = part.headers.match(/filename="([^"]+)"/);
      
      if (nameMatch) {
        const name = nameMatch[1];
        if (name === 'file' && filenameMatch) {
          pdfFile = part.content;
          console.log("Found PDF file:", filenameMatch[1], "size:", part.content.length);
        } else {
          fields[name] = part.content.toString();
        }
      }
    }

    if (!pdfFile) {
      return res.status(400).json({ error: "No PDF file found in request" });
    }

    // Create JWT
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      client_id: clientId,
      doc_name: fields.doc_name || 'document.pdf',
      sign_locations: [{
        page: 1,
        x: 0.72,
        y: 0.05
      }],
      iat: now,
      exp: now + 300,
      jti: crypto.randomUUID(),
      webhook_url: webhookBase ? `${webhookBase}/api/webhook/singpass` : undefined
    };

    if (fields.signer_nric) {
      payload.signer_uin_hash = crypto
        .createHash('sha256')
        .update(fields.signer_nric.trim().toUpperCase())
        .digest('hex');
    }

    console.log("JWT payload:", payload);

    // Create JWT
    const header = Buffer.from(JSON.stringify({ 
      alg: 'ES256', 
      typ: 'JWT', 
      kid: kid 
    })).toString('base64url');
    
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const message = `${header}.${body}`;
    
    const key = crypto.createPrivateKey({
      key: pem,
      format: 'pem',
      type: 'pkcs8'
    });
    
    const signature = crypto.sign('sha256', Buffer.from(message), {
      key: key,
      dsaEncoding: 'ieee-p1363'
    });
    
    const token = `${message}.${signature.toString('base64url')}`;
    console.log("JWT created successfully");

    // Try to connect to Singpass
    const apiUrl = fields.staging === '0' 
      ? 'https://api.sign.singpass.gov.sg/v3/signing-sessions'
      : 'https://stg.api.sign.singpass.gov.sg/v3/signing-sessions';

    console.log("Attempting to connect to:", apiUrl);

    // Use native https module for more control
    const result = await new Promise((resolve, reject) => {
      const url = new URL(apiUrl);
      
      const options = {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/pdf',
          'Content-Length': pdfFile.length,
          'User-Agent': 'Singpass-App/1.0'
        },
        timeout: 10000
      };

      console.log("HTTPS request options:", {
        hostname: options.hostname,
        path: options.path,
        method: options.method
      });

      const req = https.request(options, (response) => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString();
          console.log("Response status:", response.statusCode);
          console.log("Response headers:", response.headers);
          console.log("Response body length:", body.length);
          
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: body
          });
        });
      });

      req.on('error', (error) => {
        console.error("Request error:", {
          message: error.message,
          code: error.code,
          stack: error.stack
        });
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.write(pdfFile);
      req.end();
    });

    if (result.status >= 200 && result.status < 300) {
      try {
        const data = JSON.parse(result.body);
        return res.status(200).json({
          sign_request_id: data.request_id,
          signing_url: data.signing_url,
          exchange_code: data.exchange_code
        });
      } catch (e) {
        return res.status(502).json({
          error: "Invalid JSON response",
          body: result.body.substring(0, 200)
        });
      }
    } else {
      return res.status(502).json({
        error: `Singpass API returned ${result.status}`,
        body: result.body.substring(0, 200)
      });
    }

  } catch (error) {
    console.error("Fatal error:", {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    
    return res.status(500).json({
      error: "Failed to connect to Singpass API",
      message: error.message,
      code: error.code,
      suggestion: "Run /api/diagnose to check connectivity"
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false
  }
};
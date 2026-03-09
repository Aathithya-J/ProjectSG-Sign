const crypto = require('crypto');
const https = require('https');

// Correct endpoints based on diagnostic
const STAGING_URL = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL = "https://sign.singpass.gov.sg/api/v3/sign-requests";

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    console.log("Request received:", {
      method: req.method,
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
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    
    if (!boundaryMatch) {
      return res.status(400).json({ error: "No boundary in content-type" });
    }

    const boundary = boundaryMatch[1];
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
      exp: now + 300, // 5 minutes
      jti: crypto.randomUUID(),
    };

    // Add webhook URL if available
    if (webhookBase) {
      payload.webhook_url = `${webhookBase}/api/webhook/singpass`;
    }

    // Add signer NRIC hash if provided
    if (fields.signer_nric) {
      payload.signer_uin_hash = crypto
        .createHash('sha256')
        .update(fields.signer_nric.trim().toUpperCase())
        .digest('hex');
    }

    console.log("JWT payload:", JSON.stringify(payload, null, 2));

    // Create JWT
    const header = {
      alg: 'ES256',
      typ: 'JWT',
      kid: kid
    };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const bodyB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const message = `${headerB64}.${bodyB64}`;
    
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

    // Use the correct endpoint based on staging flag
    const isStaging = fields.staging !== '0'; // Default to staging
    const apiUrl = isStaging ? STAGING_URL : PROD_URL;

    console.log("Attempting to connect to:", apiUrl);
    console.log("Using staging:", isStaging);

    // Use native https module
    const result = await new Promise((resolve, reject) => {
      const url = new URL(apiUrl);
      
      const options = {
        hostname: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/pdf',
          'Content-Length': pdfFile.length,
          'User-Agent': 'Singpass-App/1.0'
        },
        timeout: 15000 // 15 second timeout
      };

      console.log("HTTPS request options:", {
        hostname: options.hostname,
        path: options.path,
        method: options.method,
        headers: Object.keys(options.headers)
      });

      const req = https.request(options, (response) => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString();
          console.log("Response status:", response.statusCode);
          console.log("Response headers:", response.headers);
          console.log("Response body:", body.substring(0, 500));
          
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
        reject(new Error('Request timeout after 15 seconds'));
      });

      req.write(pdfFile);
      req.end();
    });

    // Handle response
    if (result.status >= 200 && result.status < 300) {
      try {
        const data = JSON.parse(result.body);
        
        // Check if we got the expected response
        if (!data.request_id || !data.signing_url) {
          return res.status(502).json({
            error: "Incomplete response from Singpass",
            expected: ["request_id", "signing_url", "exchange_code"],
            received: Object.keys(data),
            data: data
          });
        }

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
      // Handle error response
      let errorDetail = result.body;
      try {
        const errorData = JSON.parse(result.body);
        errorDetail = errorData;
      } catch (e) {
        // Keep as string if not JSON
      }

      return res.status(502).json({
        error: `Singpass API returned ${result.status}`,
        status: result.status,
        detail: errorDetail,
        url: apiUrl
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
      suggestion: "Check that you're using the correct API endpoints"
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false
  }
};
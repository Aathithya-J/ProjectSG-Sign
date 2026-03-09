const crypto = require('crypto');

const STAGING_URL = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";
const PROD_URL = "https://sign.singpass.gov.sg/api/v3/sign-requests";

function createJWT(payload, pem, kid) {
  // Clean up the PEM - remove any escaped newlines
  const cleanPem = pem.replace(/\\n/g, '\n').trim();
  
  console.log("PEM starts with:", cleanPem.substring(0, 50));
  
  // Create header
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid: kid
  };
  
  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const bodyB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const message = `${headerB64}.${bodyB64}`;
  
  // Try different key formats
  let key;
  const errors = [];
  
  // Try PKCS#8 format (-----BEGIN PRIVATE KEY-----)
  try {
    key = crypto.createPrivateKey({
      key: cleanPem,
      format: 'pem',
      type: 'pkcs8'
    });
    console.log("Successfully loaded as PKCS#8");
  } catch (err) {
    errors.push(`PKCS#8: ${err.message}`);
    
    // Try SEC1 format (-----BEGIN EC PRIVATE KEY-----)
    try {
      key = crypto.createPrivateKey({
        key: cleanPem,
        format: 'pem',
        type: 'sec1'
      });
      console.log("Successfully loaded as SEC1");
    } catch (err2) {
      errors.push(`SEC1: ${err2.message}`);
      
      // Try without specifying type
      try {
        key = crypto.createPrivateKey(cleanPem);
        console.log("Successfully loaded with auto-detection");
      } catch (err3) {
        errors.push(`Auto: ${err3.message}`);
        throw new Error(`Failed to load private key. Errors: ${errors.join(' | ')}`);
      }
    }
  }
  
  // Sign the message
  const signature = crypto.sign('sha256', Buffer.from(message), {
    key: key,
    dsaEncoding: 'ieee-p1363'
  });
  
  return `${message}.${signature.toString('base64url')}`;
}

module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const clientId = process.env.SINGPASS_CLIENT_ID;
    const pem = process.env.SINGPASS_PRIVATE_KEY_PEM || '';
    const kid = process.env.SINGPASS_KID;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    console.log("Environment check:", {
      clientId: clientId ? '✓' : '✗',
      pemLength: pem.length,
      kid: kid ? '✓' : '✗',
      webhookBase: webhookBase || '✗'
    });

    // Parse multipart form data
    const chunks = [];
    await new Promise((resolve, reject) => {
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', resolve);
      req.on('error', reject);
    });
    
    const rawBody = Buffer.concat(chunks);
    
    // Simple multipart parser
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    
    if (!boundaryMatch) {
      return res.status(400).json({ error: "No boundary in content-type" });
    }

    const boundary = boundaryMatch[1];
    const boundaryBuffer = Buffer.from(`--${boundary}`);
    
    // Parse parts (simplified - you may want to use a proper multipart parser)
    let pdfFile = null;
    const fields = {};
    
    // For simplicity in this example, assume the file is the largest part
    // In production, use a proper multipart parser
    
    // For now, we'll just extract the file by looking for PDF signature
    const pdfStart = rawBody.indexOf('%PDF-');
    if (pdfStart !== -1) {
      pdfFile = rawBody.slice(pdfStart);
      console.log("Found PDF, size:", pdfFile.length);
    } else {
      return res.status(400).json({ error: "No PDF file found" });
    }

    // Create JWT payload
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      client_id: clientId,
      doc_name: 'document.pdf',
      sign_locations: [{
        page: 1,
        x: 0.72,
        y: 0.05
      }],
      iat: now,
      exp: now + 300,
      jti: crypto.randomUUID(),
    };

    // Add webhook if available
    if (webhookBase) {
      payload.webhook_url = `${webhookBase}/api/webhook/singpass`;
    }

    console.log("Creating JWT with payload:", JSON.stringify(payload, null, 2));

    // Create JWT token
    let token;
    try {
      token = createJWT(payload, pem, kid);
      console.log("JWT created successfully");
      
      // Log first 50 chars of token for debugging
      console.log("Token starts with:", token.substring(0, 50) + "...");
    } catch (jwtError) {
      console.error("JWT creation failed:", jwtError);
      return res.status(500).json({
        error: "Failed to create JWT",
        detail: jwtError.message
      });
    }

    // Try staging endpoint
    const apiUrl = STAGING_URL;
    console.log("Calling Singpass API:", apiUrl);

    // Make the request
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/pdf',
        'User-Agent': 'Singpass-App/1.0'
      },
      body: pdfFile
    });

    const responseText = await response.text();
    console.log("Response status:", response.status);
    console.log("Response headers:", Object.fromEntries(response.headers));
    console.log("Response body:", responseText);

    if (!response.ok) {
      return res.status(response.status).json({
        error: `Singpass API returned ${response.status}`,
        detail: responseText,
        headers: Object.fromEntries(response.headers)
      });
    }

    // Parse response
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      return res.status(502).json({
        error: "Invalid JSON response",
        body: responseText
      });
    }

    return res.status(200).json({
      sign_request_id: data.request_id,
      signing_url: data.signing_url,
      exchange_code: data.exchange_code
    });

  } catch (error) {
    console.error("Fatal error:", error);
    return res.status(500).json({
      error: "Internal server error",
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false
  }
};
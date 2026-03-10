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
 // Replace the key loading section (from line ~40-75) with this:
let key;
const errors = [];

try {
  // Try to load as-is first
  key = crypto.createPrivateKey({
    key: cleanPem,
    format: 'pem'
  });
  console.log("Successfully loaded private key");
} catch (err) {
  console.error("Failed to load private key:", err.message);
  
  // If it's an unsupported format error, try to convert it
  if (err.message.includes('UNSUPPORTED')) {
    try {
      // For ES256 keys, we need to ensure it's in PKCS#8 format
      // Since we can't convert in code easily, we'll throw a clear error
      throw new Error(
        'Private key format not supported. Please use the converted PKCS#8 format:\n' +
        '-----BEGIN PRIVATE KEY-----\n' +
        'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4ICYKDqxAySgsUxR\n' +
        'nNA59LWMoppfM5wFXef1hc59yGOhRANCAATSb2hIeqgEZBpVmEeSa3+DN2QIREi9\n' +
        'RXdXpXWvLmpErYNZ3yhBRlyCcA1PgK0LBHX10Ga7mytObYM3ZPq9Hr5Z\n' +
        '-----END PRIVATE KEY-----'
      );
    } catch (conversionError) {
      throw conversionError;
    }
  } else {
    throw err;
  }
}
  
  // Sign the message
  const signature = crypto.sign('sha256', Buffer.from(message), {
    key: key,
    dsaEncoding: 'ieee-p1363'
  });
  
  return `${message}.${signature.toString('base64url')}`;
}

// Helper function to parse multipart form data
function parseMultipart(body, boundary) {
  const parts = [];
  const boundaryBuffer = Buffer.from(`--${boundary}`);
  let start = 0;
  
  while (start < body.length) {
    // Find next boundary
    const boundaryIndex = body.indexOf(boundaryBuffer, start);
    if (boundaryIndex === -1) break;
    
    start = boundaryIndex + boundaryBuffer.length;
    
    // Check if this is the last boundary
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break;
    
    // Skip CRLF after boundary
    if (body[start] === 0x0d) start += 2;
    
    // Find end of headers
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), start);
    if (headerEnd === -1) break;
    
    // Extract headers
    const headers = body.slice(start, headerEnd).toString();
    start = headerEnd + 4;
    
    // Find next boundary to determine content end
    const nextBoundary = body.indexOf(boundaryBuffer, start);
    const contentEnd = nextBoundary !== -1 ? nextBoundary - 2 : body.length;
    const content = body.slice(start, contentEnd);
    
    // Parse headers to get field info
    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    
    parts.push({
      headers,
      name: nameMatch ? nameMatch[1] : null,
      filename: filenameMatch ? filenameMatch[1] : null,
      content
    });
    
    start = nextBoundary !== -1 ? nextBoundary : body.length;
  }
  
  return parts;
}

module.exports = async function handler(req, res) {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  
  // Only allow POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    // Get environment variables
    const clientId = process.env.SINGPASS_CLIENT_ID;

    const pem = process.env.SINGPASS_PRIVATE_KEY || process.env.SINGPASS_PRIVATE_KEY_PEM || '';

    const kid = process.env.SINGPASS_KID;
    const webhookBase = process.env.WEBHOOK_BASE_URL;

    // Log environment check (without exposing sensitive data)
    console.log("Environment check:", {
      clientId: clientId ? '✓' : '✗',
      pemLength: pem.length,
      kid: kid ? '✓' : '✗',
      webhookBase: webhookBase || '✗'
    });

    // Validate required env vars
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

    // Read raw request body
    const chunks = [];
    await new Promise((resolve, reject) => {
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', resolve);
      req.on('error', reject);
    });
    
    const rawBody = Buffer.concat(chunks);
    console.log("Raw body size:", rawBody.length);
    
    // Get content type and extract boundary
    const contentType = req.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    
    if (!boundaryMatch) {
      return res.status(400).json({ 
        error: "No boundary in content-type",
        contentType 
      });
    }

    // Parse multipart data
    const boundary = boundaryMatch[1];
    const parts = parseMultipart(rawBody, boundary);
    
    console.log(`Found ${parts.length} parts in multipart data`);
    
    // Extract PDF file and form fields
    let pdfFile = null;
    let fileName = 'document.pdf';
    const fields = {};

    for (const part of parts) {
      if (part.name === 'file' && part.filename) {
        pdfFile = part.content;
        fileName = part.filename;
        console.log(`Found PDF file: ${fileName}, size: ${part.content.length} bytes`);
        
        // Verify PDF signature (starts with %PDF)
        if (part.content.length > 4 && 
            part.content[0] === 0x25 && // %
            part.content[1] === 0x50 && // P
            part.content[2] === 0x44 && // D
            part.content[3] === 0x46) { // F
          console.log("✓ PDF signature verified");
        } else {
          console.log("⚠ Warning: File may not be a valid PDF");
        }
      } else if (part.name) {
        fields[part.name] = part.content.toString();
        console.log(`Found field: ${part.name} = ${fields[part.name]}`);
      }
    }

    // Validate PDF file
    if (!pdfFile) {
      return res.status(400).json({ 
        error: "No PDF file found in request",
        partsFound: parts.map(p => ({ 
          name: p.name, 
          hasFilename: !!p.filename,
          size: p.content.length 
        }))
      });
    }

    // Get staging flag from form fields (default to true for staging)
    const isStaging = fields.staging !== 'false' && fields.staging !== '0';
    
    // Get document name from fields or use filename
    const docName = fields.doc_name || fileName;
    
    // Create JWT payload
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      client_id: clientId,
      doc_name: docName,
      sign_locations: [{
        page: 1,
        x: 0.72,
        y: 0.05
      }],
      iat: now,
      exp: now + 300, // 5 minutes
      jti: crypto.randomUUID(),
    };

    // Add webhook if available
    if (webhookBase) {
      payload.webhook_url = `${webhookBase}/api/webhook/singpass`;
    }

    // Add signer NRIC hash if provided
    if (fields.signer_nric) {
      const nricHash = crypto
        .createHash('sha256')
        .update(fields.signer_nric.trim().toUpperCase())
        .digest('hex');
      payload.signer_uin_hash = nricHash;
      console.log("Added signer NRIC hash");
    }

    console.log("JWT payload:", JSON.stringify(payload, null, 2));

    // Create JWT token
    let token;
    try {
      token = createJWT(payload, pem, kid);
      console.log("✓ JWT created successfully");
      console.log("Token starts with:", token.substring(0, 50) + "...");
    } catch (jwtError) {
      console.error("✗ JWT creation failed:", jwtError);
      return res.status(500).json({
        error: "Failed to create JWT",
        detail: jwtError.message
      });
    }

    // Select API endpoint based on staging flag
    const apiUrl = isStaging ? STAGING_URL : PROD_URL;
    console.log(`Calling Singpass API (${isStaging ? 'staging' : 'production'}):`, apiUrl);

    // Make request to Singpass
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/octet-stream',
        'User-Agent': 'Singpass-App/1.0'
      },
      body: pdfFile
    });

    // Get response
    const responseText = await response.text();
    console.log("Response status:", response.status);
    console.log("Response headers:", Object.fromEntries(response.headers));
    
    // Log response body (first 500 chars only to avoid huge logs)
    console.log("Response body:", responseText.substring(0, 500));

    // Handle error responses
    if (!response.ok) {
      let errorDetail = responseText;
      try {
        // Try to parse as JSON for better error details
        const errorJson = JSON.parse(responseText);
        errorDetail = errorJson;
      } catch (e) {
        // Keep as text if not JSON
      }

      return res.status(response.status).json({
        error: `Singpass API returned ${response.status}`,
        detail: errorDetail,
        headers: Object.fromEntries(response.headers)
      });
    }

    // Parse successful response
    let data;
    try {
      data = JSON.parse(responseText);
    } catch (e) {
      return res.status(502).json({
        error: "Invalid JSON response from Singpass",
        body: responseText.substring(0, 200)
      });
    }

    // Validate response has required fields
    if (!data.request_id || !data.signing_url) {
      return res.status(502).json({
        error: "Incomplete response from Singpass",
        expected: ["request_id", "signing_url", "exchange_code"],
        received: Object.keys(data),
        data: data
      });
    }

    // Return success response
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
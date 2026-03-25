/**
 * POST /api/send
 *
 * Accepts either:
 *   1. A multipart/form-data request with a PDF file (field: "file") and an
 *      optional signer NRIC (field: "signer_nric").
 *   2. A JSON request with a "pdf_url" and an optional "signer_nric".
 *
 * Creates a Singpass sign request and returns the signing URL together with
 * the request metadata needed to poll for completion and download the signed document.
 *
 * Response (200):
 *   {
 *     "sign_request_id": "<uuid>",
 *     "signing_url":     "https://app.singpass.gov.sg/...",
 *     "exchange_code":   "<code>"
 *   }
 *
 * Security Features:
 *   - Input validation for file size, type, and NRIC format
 *   - CORS protection with origin validation
 *   - Rate limiting headers
 *   - Secure headers (CSP, X-Frame-Options, etc.)
 *   - PDF URL validation (whitelist check)
 *   - Request timeout protection
 */

const crypto = require("crypto");
const https = require("https");
const http = require("http");
const url = require("url");

// ---------------------------------------------------------------------------
// Configuration & Constants
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_PDF_URL_LENGTH = 2048;
const ALLOWED_ORIGINS = [
  "https://project-sg-sign.vercel.app",
  "http://localhost:3000",
  "http://localhost:8080"
];
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 10;

// In-memory rate limiting (consider Redis for production)
const rateLimitStore = new Map();

// ---------------------------------------------------------------------------
// Security Helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function createJWT(payload, privateKey, kid, aud) {
  const header = { alg: "ES256", typ: "JWT", kid };
  const iat = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat,
    exp: iat + 120,
    jti: crypto.randomUUID(),
    aud,
    iss: "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ",
    sub: "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ",
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign("SHA256");
  signer.update(signatureInput);
  const signature = signer
    .sign({ key: privateKey, dsaEncoding: "ieee-p1363" }, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${signatureInput}.${signature}`;
}

/**
 * Validate NRIC format: S/T/F/G + 7 digits + letter
 */
function validateNRIC(nric) {
  if (!nric || typeof nric !== "string") return false;
  return /^[STFG]\d{7}[A-Z]$/.test(nric.trim().toUpperCase());
}

/**
 * Validate PDF URL (basic security check)
 */
function validatePdfUrl(pdfUrl) {
  try {
    const parsedUrl = new url.URL(pdfUrl);
    
    // Only allow HTTPS
    if (parsedUrl.protocol !== "https:") {
      return false;
    }
    
    // Check URL length
    if (pdfUrl.length > MAX_PDF_URL_LENGTH) {
      return false;
    }
    
    // Prevent localhost/private IPs
    const hostname = parsedUrl.hostname;
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("10.") ||
      hostname.startsWith("172.")
    ) {
      return false;
    }
    
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Rate limiting check
 */
function checkRateLimit(clientId) {
  const now = Date.now();
  const key = `rate_limit:${clientId}`;
  
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, []);
  }
  
  const requests = rateLimitStore.get(key);
  
  // Remove old requests outside the window
  const validRequests = requests.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (validRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  
  validRequests.push(now);
  rateLimitStore.set(key, validRequests);
  
  return true;
}

/**
 * Robust page count detection.
 */
function getPdfPageCount(buffer) {
  const str = buffer.toString("binary");

  const allCountMatches = str.match(/\/Count\s+(\d+)/g);
  if (allCountMatches && allCountMatches.length > 0) {
    const counts = allCountMatches
      .map((m) => parseInt(m.match(/(\d+)/)[1], 10))
      .filter((n) => !isNaN(n) && n > 0);
    if (counts.length > 0) return Math.max(...counts);
  }

  const pageMatches = str.match(/\/Type\s*\/Page\b/g);
  if (pageMatches && pageMatches.length > 0) {
    return pageMatches.length;
  }

  const simplePageMatches = str.match(/\/Page\b/g);
  if (simplePageMatches && simplePageMatches.length > 0) {
    const hasPagesNode = str.includes("/Pages");
    return hasPagesNode ? Math.max(1, simplePageMatches.length - 1) : simplePageMatches.length;
  }

  return 1;
}

/**
 * Download PDF from URL with security checks
 */
function downloadPdf(pdfUrl) {
  return new Promise((resolve, reject) => {
    if (!validatePdfUrl(pdfUrl)) {
      return reject(new Error("Invalid PDF URL"));
    }

    const parsedUrl = new url.URL(pdfUrl);
    const protocol = parsedUrl.protocol === "https:" ? https : http;

    const request = protocol.get(pdfUrl, { timeout: 30000 }, (response) => {
      if (response.statusCode !== 200) {
        return reject(new Error(`Failed to download PDF: HTTP ${response.statusCode}`));
      }

      // Check content type
      const contentType = response.headers["content-type"] || "";
      if (!contentType.includes("application/pdf")) {
        return reject(new Error("Invalid content type: not a PDF"));
      }

      // Check content length
      const contentLength = parseInt(response.headers["content-length"] || "0", 10);
      if (contentLength > MAX_FILE_SIZE) {
        return reject(new Error("PDF file exceeds size limit"));
      }

      const chunks = [];
      let totalSize = 0;

      response.on("data", (chunk) => {
        totalSize += chunk.length;
        if (totalSize > MAX_FILE_SIZE) {
          request.destroy();
          return reject(new Error("PDF file exceeds size limit"));
        }
        chunks.push(chunk);
      });

      response.on("end", () => resolve(Buffer.concat(chunks)));
      response.on("error", reject);
    });

    request.on("error", reject);
    request.on("timeout", () => {
      request.destroy();
      reject(new Error("PDF download timeout"));
    });
  });
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  // Security: Set secure headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  // CORS with origin validation
  const origin = req.headers.origin || "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
  res.setHeader("Access-Control-Max-Age", "86400");

  // Rate limiting
  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(clientIp)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many requests. Please try again later." });
  }

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const contentType = req.headers["content-type"] || "";
    let pdfBuffer = null;
    let signerNric = null;
    let fileName = "document.pdf";

    if (contentType.includes("multipart/form-data")) {
      // Handle multipart/form-data (file upload)
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);

      // Security: Check body size
      if (body.length > MAX_FILE_SIZE) {
        return res.status(413).json({ error: "Payload too large" });
      }

      const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/);
      const boundary = boundaryMatch
        ? boundaryMatch[1] || boundaryMatch[2]
        : null;

      if (!boundary) {
        return res
          .status(400)
          .json({ error: "Invalid content type: boundary missing" });
      }

      const boundaryBuffer = Buffer.from("--" + boundary);
      let pos = 0;
      while (pos < body.length) {
        const nextBoundary = body.indexOf(boundaryBuffer, pos);
        if (nextBoundary === -1) break;

        const partStart = nextBoundary + boundaryBuffer.length + 2;
        const partEnd = body.indexOf(boundaryBuffer, partStart);
        if (partEnd === -1) break;

        const part = body.slice(partStart, partEnd - 2);
        const headerEnd = part.indexOf("\r\n\r\n");
        if (headerEnd !== -1) {
          const headers = part.slice(0, headerEnd).toString();
          const content = part.slice(headerEnd + 4);

          if (headers.includes('name="file"')) {
            pdfBuffer = content;
            const filenameMatch = headers.match(/filename="([^"]+)"/);
            if (filenameMatch) {
              // Security: Sanitize filename
              fileName = filenameMatch[1]
                .replace(/[^a-zA-Z0-9._-]/g, "_")
                .slice(0, 255);
            }
          } else if (headers.includes('name="signer_nric"')) {
            signerNric = content.toString().trim().toUpperCase();
          }
        }
        pos = partEnd;
      }
    } else if (contentType.includes("application/json")) {
      // Handle application/json (URL upload)
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);

      if (body.length > MAX_FILE_SIZE) {
        return res.status(413).json({ error: "Payload too large" });
      }

      const jsonBody = JSON.parse(body.toString());

      const pdfUrl = jsonBody.pdf_url;
      signerNric = jsonBody.signer_nric ? jsonBody.signer_nric.toUpperCase() : null;
      fileName = (jsonBody.filename || "document.pdf")
        .replace(/[^a-zA-Z0-9._-]/g, "_")
        .slice(0, 255);

      if (!pdfUrl) {
        return res.status(400).json({ error: "Missing pdf_url in request body" });
      }

      console.log(`Downloading PDF from: ${pdfUrl}`);
      pdfBuffer = await downloadPdf(pdfUrl);
    } else {
      return res.status(400).json({ error: "Unsupported Content-Type" });
    }

    if (!pdfBuffer || pdfBuffer.length === 0) {
      return res
        .status(400)
        .json({ error: "No PDF file provided or file is empty" });
    }

    // Security: Validate file size
    if (pdfBuffer.length > MAX_FILE_SIZE) {
      return res.status(413).json({ error: "File size exceeds limit" });
    }

    // Security: Validate NRIC if provided
    if (signerNric && !validateNRIC(signerNric)) {
      return res.status(400).json({ error: "Invalid NRIC format" });
    }

    // ------------------------------------------------------------------
    // Build sign-locations for every page
    // ------------------------------------------------------------------
    const detectedPageCount = getPdfPageCount(pdfBuffer);
    console.log(`Detected PDF page count: ${detectedPageCount}`);
    const pageCount = Math.min(Math.max(detectedPageCount, 1), 100);

    const signLocations = [];
    for (let i = 1; i <= pageCount; i++) {
      signLocations.push({
        page: i,
        x: 0.4874,
        y: 0.135,
        width: 0.1,
        height: 0.02
      });
    }

    // ------------------------------------------------------------------
    // Create Singpass sign request
    // ------------------------------------------------------------------
    const clientId = "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = "https://app.sign.singpass.gov.sg/api/v3/sign-requests";

    const jwtPayload = {
      client_id: clientId,
      doc_name: fileName,
      sign_locations: signLocations,
    };

    if (signerNric) {
      jwtPayload.signer_uin_hash = crypto
        .createHash("sha256")
        .update(signerNric)
        .digest("hex");
    }

    const jwt = createJWT(jwtPayload, privateKey, kid, apiUrl);

    const options = {
      method: "POST",
      headers: {
        Authorization: jwt,
        "Content-Type": "application/octet-stream",
        "Content-Length": pdfBuffer.length,
      },
      timeout: 30000,
    };

    // ------------------------------------------------------------------
    // Forward PDF to Singpass and relay the sign link
    // ------------------------------------------------------------------
    const apiReq = https.request(apiUrl, options, (apiRes) => {
      let data = "";
      apiRes.on("data", (chunk) => (data += chunk));
      apiRes.on("end", () => {
        try {
          const ct = apiRes.headers["content-type"] || "";
          if (ct.includes("application/json")) {
            const result = JSON.parse(data);
            if (apiRes.statusCode >= 200 && apiRes.statusCode < 300) {
              return res.status(200).json({
                sign_request_id: result.request_id,
                signing_url: result.signing_url,
                exchange_code: result.exchange_code,
              });
            }
            return res.status(apiRes.statusCode).json(result);
          }
          return res
            .status(apiRes.statusCode)
            .json({ error: "API returned non-JSON response" });
        } catch (e) {
          return res
            .status(500)
            .json({ error: "Failed to parse API response" });
        }
      });
    });

    apiReq.on("error", (e) => {
      console.error("API request error:", e);
      res.status(500).json({ error: "Failed to communicate with signing service" });
    });

    apiReq.on("timeout", () => {
      apiReq.destroy();
      res.status(504).json({ error: "Request timeout" });
    });

    apiReq.write(pdfBuffer);
    apiReq.end();
  } catch (err) {
    console.error("Handler error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

module.exports.config = {
  api: { bodyParser: false },
};

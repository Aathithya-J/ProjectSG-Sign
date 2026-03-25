/**
 * GET /api/status?id=<sign_request_id>&exchange_code=<code>
 *
 * Queries the signing status and returns the signed document URL if ready.
 *
 * Security Features:
 *   - Input validation for request ID and exchange code
 *   - Secure headers (CSP, X-Frame-Options, etc.)
 *   - CORS protection with origin validation
 *   - Request timeout protection
 *   - Rate limiting
 */

const crypto = require("crypto");
const https = require("https");

// ---------------------------------------------------------------------------
// Configuration & Constants
// ---------------------------------------------------------------------------

const ALLOWED_ORIGINS = [
  "https://project-sg-sign.vercel.app",
  "http://localhost:3000",
  "http://localhost:8080"
];

const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 20;

// In-memory rate limiting
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
 * Validate request ID format (UUID)
 */
function validateRequestId(id) {
  if (!id || typeof id !== "string") return false;
  return /^[a-f0-9-]{36}$/.test(id.toLowerCase());
}

/**
 * Validate exchange code format
 */
function validateExchangeCode(code) {
  if (!code || typeof code !== "string") return false;
  return /^[a-zA-Z0-9_-]{20,}$/.test(code);
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
  const validRequests = requests.filter(time => now - time < RATE_LIMIT_WINDOW);
  
  if (validRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  
  validRequests.push(now);
  rateLimitStore.set(key, validRequests);
  
  return true;
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
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");

  // CORS with origin validation
  const origin = req.headers.origin || "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");

  // Rate limiting
  const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  if (!checkRateLimit(clientIp)) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many requests. Please try again later." });
  }

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { id, exchange_code } = req.query;

    // Security: Validate inputs
    if (!id || !exchange_code) {
      return res.status(400).json({ error: "Missing required parameters: id, exchange_code" });
    }

    if (!validateRequestId(id)) {
      return res.status(400).json({ error: "Invalid request ID format" });
    }

    if (!validateExchangeCode(exchange_code)) {
      return res.status(400).json({ error: "Invalid exchange code format" });
    }

    const clientId = "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = `https://app.sign.singpass.gov.sg/api/v3/sign-requests/${id}/signed-doc`;

    const jwtPayload = {
      client_id: clientId,
      exchange_code: exchange_code,
    };

    const jwt = createJWT(jwtPayload, privateKey, kid, apiUrl);

    const options = {
      method: "GET",
      headers: {
        Authorization: jwt,
        Accept: "application/json",
      },
      timeout: 30000,
    };

    const apiReq = https.request(apiUrl, options, (apiRes) => {
      let data = "";
      apiRes.on("data", (chunk) => (data += chunk));
      apiRes.on("end", () => {
        try {
          const ct = apiRes.headers["content-type"] || "";
          if (ct.includes("application/json")) {
            const result = JSON.parse(data);
            
            if (apiRes.statusCode === 200) {
              return res.status(200).json({ 
                status: "signed", 
                signed_doc_url: result.signed_doc_url 
              });
            } else if (apiRes.statusCode === 202) {
              return res.status(200).json({ status: "pending" });
            } else if (apiRes.statusCode === 400) {
              const error = result.error || "Unknown error";
              if (error === "DOCUMENT_NOT_SIGNED") {
                return res.status(200).json({ status: "pending" });
              } else if (error === "REQUEST_EXPIRED") {
                return res.status(200).json({ status: "expired", error: "Signing request has expired" });
              } else if (error === "REQUEST_CANCELLED") {
                return res.status(200).json({ status: "cancelled", error: "Signing request was cancelled" });
              } else if (error === "REQUEST_FAILED") {
                return res.status(200).json({ status: "failed", error: "Signing request failed" });
              }
            }
            
            return res.status(200).json({ status: "failed", error: result.error || "Unknown error" });
          }
          return res.status(apiRes.statusCode).json({ error: "API returned non-JSON response" });
        } catch (e) {
          console.error("Parse error:", e);
          return res.status(500).json({ error: "Failed to parse API response" });
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

    apiReq.end();
  } catch (err) {
    console.error("Handler error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};

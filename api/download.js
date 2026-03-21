const https = require("https");
const crypto = require("crypto");

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function createJWT(payload, privateKey, kid, aud) {
  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: kid,
  };
  const iat = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: iat,
    exp: iat + 120,
    jti: crypto.randomUUID(),
    aud: aud,
    iss: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4",
    sub: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4",
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

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { id, exchange_code } = req.query;

  if (!id || !exchange_code) {
    return res.status(400).json({ error: "Missing sign_request_id or exchange_code" });
  }

  const clientId = "WTYhkYnUJubcEOzDokeJO4szhblsEzF4";
  const kid = "key-1";
  const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

  const apiUrl = `https://staging.sign.singpass.gov.sg/api/v3/sign-requests/${id}/signed-doc`;
  const jwt = createJWT(
    {
      client_id: clientId,
      exchange_code: exchange_code,
    },
    privateKey,
    kid,
    apiUrl
  );

  const options = {
    method: "GET",
    headers: {
      Authorization: jwt,
      Accept: "application/pdf",
    },
  };

  const apiReq = https.request(apiUrl, options, (apiRes) => {
    const contentType = apiRes.headers["content-type"] || "";
    const isPdf = contentType.includes("application/pdf");
    const isSuccess = apiRes.statusCode === 200;

    if (isSuccess && isPdf) {
      // Stream the PDF directly to the client
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", "attachment; filename=signed_document.pdf");
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      apiRes.pipe(res);
    } else {
      // Collect the response body for error handling
      let data = "";
      apiRes.on("data", (chunk) => {
        data += chunk;
      });
      apiRes.on("end", () => {
        // Always return JSON for non-PDF responses
        res.setHeader("Content-Type", "application/json");

        if (isSuccess && !isPdf) {
          // Success but not a PDF (unexpected)
          res.status(200).json({
            error: "Expected PDF but received " + contentType,
            raw: data.substring(0, 500),
          });
        } else if (apiRes.statusCode === 400) {
          // Try to parse as JSON for 400 errors
          try {
            const result = JSON.parse(data);
            res.status(400).json(result);
          } catch (e) {
            res.status(400).json({
              error: "Document not yet signed or invalid request",
              raw: data,
            });
          }
        } else if (apiRes.statusCode === 401 || apiRes.statusCode === 403) {
          res.status(apiRes.statusCode).json({
            error: "Authentication failed. Please try signing again.",
          });
        } else {
          // Generic error response
          res.status(apiRes.statusCode || 500).json({
            error: "Failed to retrieve signed document",
            status: apiRes.statusCode,
            details: data.substring(0, 500),
          });
        }
      });
    }
  });

  apiReq.on("error", (e) => {
    console.error("API request error:", e);
    res.status(500).json({
      error: "Failed to connect to signing service",
      details: e.message,
    });
  });

  apiReq.end();
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};

const https = require("https");
const http = require("http");
const crypto = require("crypto");
const url = require("url");

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
    exp: iat + 120, // Valid for 2 minutes
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

/**
 * Robust page count detection.
 * Matches ALL /Count entries in the PDF and returns the maximum value, which
 * corresponds to the root /Pages node (sub-tree nodes have smaller counts).
 */
function getPdfPageCount(buffer) {
  const str = buffer.toString("binary");

  // 1. Match /Count entries and take the largest.
  // In a PDF Page Tree, the root node's /Count is the total page count.
  const allCountMatches = str.match(/\/Count\s+(\d+)/g);
  if (allCountMatches && allCountMatches.length > 0) {
    const counts = allCountMatches
      .map((m) => parseInt(m.match(/(\d+)/)[1], 10))
      .filter((n) => !isNaN(n) && n > 0);
    if (counts.length > 0) return Math.max(...counts);
  }

  // 2. Fallback: Count explicit page objects (/Type /Page).
  const pageMatches = str.match(/\/Type\s*\/Page\b/g);
  if (pageMatches && pageMatches.length > 0) {
    return pageMatches.length;
  }

  // 3. Second Fallback: Search for /Page without /Type.
  const simplePageMatches = str.match(/\/Page\b/g);
  if (simplePageMatches && simplePageMatches.length > 0) {
    // If /Pages (plural) exists, one match is likely the root node, so subtract 1.
    const hasPagesNode = str.includes("/Pages");
    return hasPagesNode ? Math.max(1, simplePageMatches.length - 1) : simplePageMatches.length;
  }

  return 1;
}

// Download PDF from URL
function downloadPdf(pdfUrl) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new url.URL(pdfUrl);
    const protocol = parsedUrl.protocol === "https:" ? https : http;

    const request = protocol.get(pdfUrl, (response) => {
      if (response.statusCode !== 200) {
        return reject(new Error(`Failed to download PDF: HTTP ${response.statusCode}`));
      }

      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve(Buffer.concat(chunks)));
      response.on("error", reject);
    });

    request.on("error", reject);
    request.setTimeout(30000, () => {
      request.destroy();
      reject(new Error("PDF download timeout"));
    });
  });
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);
    const { pdf_url, filename, signer_nric } = JSON.parse(body.toString());

    if (!pdf_url) {
      return res.status(400).json({ error: "Missing pdf_url in request body" });
    }

    console.log(`Downloading PDF from: ${pdf_url}`);
    const pdfBuffer = await downloadPdf(pdf_url);

    if (!pdfBuffer || pdfBuffer.length === 0) {
      return res.status(400).json({ error: "Downloaded PDF is empty" });
    }

    const clientId = "WTYhkYnUJubcEOzDokeJO4szhblsEzF4";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";

    const detectedPageCount = getPdfPageCount(pdfBuffer);
    const pageCount = Math.min(Math.max(detectedPageCount, 1), 100); // Support up to 100 pages

    // Create signature locations for each page
    const signLocations = [];
    for (let i = 1; i <= pageCount; i++) {
      signLocations.push({
        page: i,
        x: 0.7,    // 70% from left (right side)
        y: 0.1,    // 10% from bottom (lower area)
        width: 0.25, // 25% width for signature box
        height: 0.05 // 5% height for signature box
      });
    }

    const docName = filename || "document.pdf";

    const jwtPayload = {
      client_id: clientId,
      doc_name: docName,
      sign_locations: signLocations
    };

    if (signer_nric) {
      jwtPayload.signer_uin_hash = crypto
        .createHash("sha256")
        .update(signer_nric.toUpperCase())
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
    };

    const apiReq = https.request(apiUrl, options, (response) => {
      let data = "";
      response.on("data", (chunk) => (data += chunk));
      response.on("end", () => {
        try {
          const result = JSON.parse(data);
          if (response.statusCode === 200 || response.statusCode === 201) {
            console.log("Sign request successful:", result);
            res.status(200).json({
              success: true,
              redirect_url: result.redirect_url,
              request_id: result.request_id,
              exchange_code: result.exchange_code,
              // Normalize for index.html compatibility
              sign_request_id: result.request_id,
              signing_url: result.signing_url
            });
          } else {
            console.error("Singpass API error:", result);
            res.status(response.statusCode || 500).json({
              success: false,
              error: result.error || "Failed to create sign request",
              details: result,
            });
          }
        } catch (e) {
          console.error("Error parsing response:", e);
          res.status(500).json({
            success: false,
            error: "Failed to parse Singpass response",
          });
        }
      });
    });

    apiReq.on("error", (error) => {
      console.error("Request error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to communicate with Singpass API",
        details: error.message,
      });
    });

    apiReq.write(pdfBuffer);
    apiReq.end();
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Internal server error",
    });
  }
};

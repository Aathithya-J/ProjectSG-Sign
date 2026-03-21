const crypto = require("crypto");
const https = require("https");

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

// Improved robust page count detection
function getPdfPageCount(buffer) {
  const str = buffer.toString("binary");
  
  const countMatch = str.match(/\/Count\s+(\d+)/);
  if (countMatch) {
    const count = parseInt(countMatch[1], 10);
    if (!isNaN(count) && count > 0) return count;
  }
  
  const pageMatches = str.match(/\/Type\s*\/Page\b/g);
  if (pageMatches) {
    return pageMatches.length;
  }
  
  const simplePageMatches = str.match(/\/Page\b/g);
  if (simplePageMatches) {
    const hasPages = str.includes("/Pages");
    return hasPages ? Math.max(1, simplePageMatches.length - 1) : simplePageMatches.length;
  }

  return 1;
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
    const contentType = req.headers["content-type"];
    const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/);
    const boundary = boundaryMatch ? (boundaryMatch[1] || boundaryMatch[2]) : null;

    if (!boundary) {
      return res.status(400).json({ error: "Invalid content type: boundary missing" });
    }

    const boundaryBuffer = Buffer.from("--" + boundary);
    let pdfBuffer = null;
    let signerNric = null;
    let fileName = "document.pdf";

    // Robust Buffer-based multipart parsing
    let pos = 0;
    while (pos < body.length) {
      const nextBoundary = body.indexOf(boundaryBuffer, pos);
      if (nextBoundary === -1) break;
      
      const partStart = nextBoundary + boundaryBuffer.length + 2; // skip boundary and \r\n
      const partEnd = body.indexOf(boundaryBuffer, partStart);
      if (partEnd === -1) break;
      
      const part = body.slice(partStart, partEnd - 2); // remove trailing \r\n
      const headerEnd = part.indexOf("\r\n\r\n");
      if (headerEnd !== -1) {
        const headers = part.slice(0, headerEnd).toString();
        const content = part.slice(headerEnd + 4);
        
        if (headers.includes('name="file"')) {
          pdfBuffer = content;
          const filenameMatch = headers.match(/filename="([^"]+)"/);
          if (filenameMatch) fileName = filenameMatch[1];
        } else if (headers.includes('name="signer_nric"')) {
          signerNric = content.toString().trim();
        }
      }
      pos = partEnd;
    }

    if (!pdfBuffer || pdfBuffer.length === 0) {
      return res.status(400).json({ error: "No PDF file provided or file is empty" });
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
    const pageCount = Math.min(Math.max(detectedPageCount, 1), 20);

    // Create signature locations for each page
    // Positioning: bottom right area of the page for visibility
    const signLocations = [];
    for (let i = 1; i <= pageCount; i++) {
      signLocations.push({
        page: i,
        x: 0.55,    // 55% from left (right side)
        y: 0.15,    // 15% from bottom (lower area)
        width: 0.35, // 35% width for signature box
        height: 0.08 // 8% height for signature box
      });
    }

    const jwtPayload = {
      client_id: clientId,
      doc_name: fileName,
      sign_locations: signLocations
    };

    if (signerNric) {
      jwtPayload.signer_uin_hash = crypto
        .createHash("sha256")
        .update(signerNric.toUpperCase())
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

    const apiReq = https.request(apiUrl, options, (apiRes) => {
      let data = "";
      apiRes.on("data", (chunk) => (data += chunk));
      apiRes.on("end", () => {
        try {
          if (
            apiRes.headers["content-type"] &&
            apiRes.headers["content-type"].includes("application/json")
          ) {
            const result = JSON.parse(data);
            if (apiRes.statusCode >= 200 && apiRes.statusCode < 300) {
              res.status(200).json({
                sign_request_id: result.request_id,
                signing_url: result.signing_url,
                exchange_code: result.exchange_code,
              });
            } else {
              res.status(apiRes.statusCode).json(result);
            }
          } else {
            res
              .status(apiRes.statusCode)
              .json({ error: "API returned non-JSON response", raw: data });
          }
        } catch (e) {
          res.status(500).json({ error: "Failed to parse API response", raw: data });
        }
      });
    });

    apiReq.on("error", (e) => {
      res.status(500).json({ error: e.message });
    });

    apiReq.write(pdfBuffer);
    apiReq.end();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};

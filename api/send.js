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
 */

const crypto = require("crypto");
const https = require("https");
const http = require("http");
const url = require("url");

// ---------------------------------------------------------------------------
// Helpers
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

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

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
            if (filenameMatch) fileName = filenameMatch[1];
          } else if (headers.includes('name="signer_nric"')) {
            signerNric = content.toString().trim();
          }
        }
        pos = partEnd;
      }
    } else if (contentType.includes("application/json")) {
      // Handle application/json (URL upload)
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const jsonBody = JSON.parse(body.toString());

      const pdfUrl = jsonBody.pdf_url;
      signerNric = jsonBody.signer_nric;
      fileName = jsonBody.filename || "document.pdf";

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

    // ------------------------------------------------------------------
    // 3. Build sign-locations for every page
    // ------------------------------------------------------------------
    const detectedPageCount = getPdfPageCount(pdfBuffer);
    console.log(`Detected PDF page count: ${detectedPageCount}`);
    const pageCount = Math.min(Math.max(detectedPageCount, 1), 100);

    const signLocations = [];
    for (let i = 1; i <= pageCount; i++) {
      signLocations.push({
        page: i,
        x: 0.5,    // 50% from left (center horizontally)
        y: 0.01,   // 1% from bottom (extremely low, safest)
        width: 0.1,  // 10% width for signature box (even smaller)
        height: 0.02 // 2% height for signature box (even smaller)
      });
      console.log(`Page ${i}: x=${signLocations[i-1].x}, y=${signLocations[i-1].y}, width=${signLocations[i-1].width}, height=${signLocations[i-1].height}`);
    }

    // ------------------------------------------------------------------
    // 4. Create Singpass sign request
    // ------------------------------------------------------------------
    const clientId = "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = "https://sign.singpass.gov.sg/api/v3/sign-requests";

    const jwtPayload = {
      client_id: clientId,
      doc_name: fileName,
      sign_locations: signLocations,
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

    // ------------------------------------------------------------------
    // 5. Forward PDF to Singpass and relay the sign link
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
            .json({ error: "API returned non-JSON response", raw: data });
        } catch (e) {
          return res
            .status(500)
            .json({ error: "Failed to parse API response", raw: data });
        }
      });
    });

    apiReq.on("error", (e) => res.status(500).json({ error: e.message }));
    apiReq.write(pdfBuffer);
    apiReq.end();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports.config = {
  api: { bodyParser: false },
};

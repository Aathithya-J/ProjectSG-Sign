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
    const boundary = contentType.split("boundary=")[1];

    if (!boundary) {
      return res.status(400).json({ error: "Invalid content type" });
    }

    const parts = body.toString("binary").split("--" + boundary);
    let pdfBuffer = null;
    let signerNric = null;
    let fileName = "document.pdf";

    for (const part of parts) {
      if (part.includes('name="file"')) {
        const headerEnd = part.indexOf("\r\n\r\n");
        const content = part.substring(headerEnd + 4, part.lastIndexOf("\r\n"));
        pdfBuffer = Buffer.from(content, "binary");
        const filenameMatch = part.match(/filename="([^"]+)"/);
        if (filenameMatch) fileName = filenameMatch[1];
      } else if (part.includes('name="signer_nric"')) {
        const headerEnd = part.indexOf("\r\n\r\n");
        signerNric = part.substring(headerEnd + 4, part.lastIndexOf("\r\n")).trim();
      }
    }

    if (!pdfBuffer) {
      return res.status(400).json({ error: "No PDF file provided" });
    }

    const clientId = "WTYhkYnUJubcEOzDokeJO4szhblsEzF4";
    const kid = "key-1";
    const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

    const apiUrl = "https://staging.sign.singpass.gov.sg/api/v3/sign-requests";

    const jwtPayload = {
      doc_name: fileName,
      sign_locations: [{ page: 1, x: 0.72, y: 0.05 }]
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

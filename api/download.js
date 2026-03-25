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

  const clientId = "_ELmUvm5LOKEBjp0-TLBe4_J8iC9J0lQ";
  const kid = "key-1";
  const privateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNbVMxiHb2ODp6/Yw
CmSfkYQoenLG7keDDINXGtTOGR6hRANCAASfQOloP4YWjS+pF5aWVsshFXahP4j9
bQotHZrdaiEpoWTtcaE/jxqjhU8t0pY6Yy7PFGY7l0jCFTOwtIj6pC50
-----END PRIVATE KEY-----`;

  const apiUrl = `https://sign.singpass.gov.sg/api/v3/sign-requests/${id}/signed-doc`;
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
      Accept: "application/json",
    },
  };

  const apiReq = https.request(apiUrl, options, (apiRes) => {
    let data = "";
    
    apiRes.on("data", (chunk) => {
      data += chunk;
    });

    apiRes.on("end", () => {
      // Check if response is not 200
      if (apiRes.statusCode !== 200) {
        res.setHeader("Content-Type", "application/json");
        try {
          const errorData = JSON.parse(data);
          res.status(apiRes.statusCode).json(errorData);
        } catch (e) {
          res.status(apiRes.statusCode).json({ error: data });
        }
        return;
      }

      // Parse JSON response to get signed_doc_url
      let signedDocUrl = null;
      try {
        const result = JSON.parse(data);
        signedDocUrl = result.signed_doc_url;
      } catch (e) {
        res.setHeader("Content-Type", "application/json");
        res.status(500).json({ error: "Failed to parse API response" });
        return;
      }

      if (!signedDocUrl) {
        res.setHeader("Content-Type", "application/json");
        res.status(400).json({ error: "No signed document URL in response" });
        return;
      }

      // Fetch the PDF from the signed_doc_url using streaming
      https.get(signedDocUrl, (pdfRes) => {
        // Check status code
        if (pdfRes.statusCode !== 200) {
          res.setHeader("Content-Type", "application/json");
          res.status(pdfRes.statusCode).json({ error: "Failed to download PDF from storage" });
          return;
        }

        // Check content type
        const pdfContentType = pdfRes.headers["content-type"] || "";
        if (!pdfContentType.includes("application/pdf") && !pdfContentType.includes("application/octet-stream")) {
          res.setHeader("Content-Type", "application/json");
          res.status(400).json({ error: "Expected PDF but received " + pdfContentType });
          return;
        }

        // Stream the PDF directly to the client
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=signed_document.pdf");
        res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        
        // Pipe the response directly - this preserves binary data
        pdfRes.pipe(res);

        pdfRes.on("error", (err) => {
          console.error("Error streaming PDF:", err);
          if (!res.headersSent) {
            res.setHeader("Content-Type", "application/json");
            res.status(500).json({ error: "Error streaming PDF: " + err.message });
          }
        });
      }).on("error", (err) => {
        console.error("Error fetching PDF from signed_doc_url:", err);
        res.setHeader("Content-Type", "application/json");
        res.status(500).json({ error: "Failed to download PDF from storage: " + err.message });
      });
    });
  });

  apiReq.on("error", (e) => {
    console.error("API request error:", e);
    res.setHeader("Content-Type", "application/json");
    res.status(500).json({ error: "Failed to connect to signing service: " + e.message });
  });

  apiReq.end();
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};

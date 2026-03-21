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

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, headers: res.headers, data });
      });
    }).on("error", reject);
  });
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
      Accept: "application/json",
    },
  };

  try {
    const apiReq = https.request(apiUrl, options, async (apiRes) => {
      let data = "";
      apiRes.on("data", (chunk) => (data += chunk));
      apiRes.on("end", async () => {
        try {
          const contentType = apiRes.headers["content-type"] || "";

          // If we get a non-200 response, return the error
          if (apiRes.statusCode !== 200) {
            res.setHeader("Content-Type", "application/json");
            let errorMsg = "Failed to retrieve signed document";
            
            if (contentType.includes("application/json")) {
              try {
                const errorData = JSON.parse(data);
                errorMsg = errorData.error || errorMsg;
              } catch (e) {
                // Ignore parse errors
              }
            }

            res.status(apiRes.statusCode).json({ error: errorMsg });
            return;
          }

          // Parse the response to get the signed_doc_url
          let signedDocUrl = null;
          if (contentType.includes("application/json")) {
            try {
              const result = JSON.parse(data);
              signedDocUrl = result.signed_doc_url;
            } catch (e) {
              res.status(500).json({ error: "Failed to parse API response" });
              return;
            }
          }

          if (!signedDocUrl) {
            res.status(400).json({ error: "No signed document URL in response" });
            return;
          }

          // Now fetch the actual PDF from the signed_doc_url
          try {
            const pdfResponse = await httpsGet(signedDocUrl);

            if (pdfResponse.statusCode !== 200) {
              res.status(pdfResponse.statusCode).json({
                error: "Failed to download signed PDF from storage",
              });
              return;
            }

            const pdfContentType = pdfResponse.headers["content-type"] || "";
            if (!pdfContentType.includes("application/pdf")) {
              res.status(400).json({
                error: "Expected PDF but received " + pdfContentType,
              });
              return;
            }

            // Stream the PDF to the client
            res.setHeader("Content-Type", "application/pdf");
            res.setHeader("Content-Disposition", "attachment; filename=signed_document.pdf");
            res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            res.end(pdfResponse.data);
          } catch (err) {
            console.error("Error fetching PDF from signed_doc_url:", err);
            res.status(500).json({
              error: "Failed to download PDF from storage",
              details: err.message,
            });
          }
        } catch (err) {
          console.error("Error processing API response:", err);
          res.status(500).json({ error: "Failed to process API response" });
        }
      });
    });

    apiReq.on("error", (e) => {
      console.error("API request error:", e);
      res.status(500).json({
        error: "Failed to connect to signing service",
        details: e.message,
      });
    });

    apiReq.end();
  } catch (err) {
    console.error("Unexpected error:", err);
    res.status(500).json({
      error: "Unexpected error",
      details: err.message,
    });
  }
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};

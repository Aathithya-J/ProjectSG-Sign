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
    alg: "RS256",
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
    iss: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4", // Issuer is the Client ID
    sub: "WTYhkYnUJubcEOzDokeJO4szhblsEzF4", // Subject is also the Client ID
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(signatureInput);
  const signature = signer
    .sign(privateKey, "base64")
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
  const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4F0GrqNRE3SuCViY56VoOUPZ1IJPSQG8xjfAwGetbH+E4bVL
h6FdcFV6giESAgc6E7xNQLVLRv2vw9zOFjNqHTbVkFhfJfiNJRyPUN/M9wqu6Bxr
uwRZei9sD686SH5sUfFJ76TMUfU8mNROt21a8gDI0qDgNI8u966V911xnzub1n21
j6bC8SyMybtRTVLt/UsjUMlbEkJ0O1F2MN567tjFL39ocgF3FhwYPx2B6/8N3ox2
OjlzKluKB/sb1PXtV2DqPoB8uf7MpytwD2hF/PJkcaZF5JwZIO7+Gm4ZMrEHsyUq
MspLGNbLSf87NanO+wQEzZJKKGQjGefgEKAGZQIDAQABAoIBABcRAVGdiUWUipr7
4JZ6Ly2p/+Bk+EVDeDaxvy+YyR/dOVpiIu6CBML6isKLp1gNiadDRfb33JIjHTmn
/wkRxqBTxZ+WMkwLUmmFFufj5mTklIhY+atrvk49R2ESbQ3Mb5L6GVWZrgbkDVOS
Cji59a5pLbxX3U0SBmxg5tqcYQTTcPp1a59/N9tMi/F9o+dt0Uol5T+EizNsfzJH
oj50cFYF9Psc6F12bIwg+KTxFDB8h55w265reA7FyHxqWN+G5yqFVDiP7q1gxA4S
OfPOwtT38gQ6IXljEfOco0hmn1J5RjeSSdhJrQf1Ng3eKEzHM0ZhElvk7k1veSqF
i8056xkCgYEA+BHITEZB9RWGSzGFa/ljXdc7rqTO4ByAdZN/A6n1WqRK27UABu/B
sBs0FNPFWmZZmUwIIxhSlCIkaqaS9arMi3mjBOeQmUk0D2P7/x7o+k40LUIGleTq
c//fEsk8StGxGqpAw0mBue45EEQMCQD8hqz8BFeifRYUqYnDe1mCILkCgYEA54k7
Q54vdJQxuenW3+bHD82jpjOPw21NGVOyxxmor23K/4W6s4QjTLrFLkCZ49nHE6rh
yZlyb8/YsgrtZUnZL8+R43tjJ+LV80mw1PM+Z5JU0X7k/fRBexS14BaU4Pu2EO1A
Lor/lfVPQtyHC/xBJaGngTeV6qyzoCDH1cmGxQ0CgYEAscCMNZtiR6tUvyyM3gGl
IejH6yxM0Gmb4qP9rzJpjLmMqkHX8yB5OSdE+meEUnJkYWQJsJwND/gnAAS76Syp
xIc0OJ91DWFW3HBYcUZEypae7I8TCPUuyk/eGCf5++KldOXp4gUZ35DDctRPi2QZ
jqcFLlddJyRbSeBdIlXQ2IECgYAoKX3GNOI2bp5RiWZkYDuXWixQ4BDH7WW6RvJz
5teD1p+nwyKnkPwuixc49qu7AkOt/a48sglPq9YCzDJxp2WtDWxY8UY53PcPxHCP
/8GLZa6gyEogYwYYu3bw7/nTLNZgCUdgy2uaL3sYNfiW86K5TFkp6OJwWpSt6gG/
670c4QKBgE5GuEX2DiwQMPQH9NhKPAZF+qaNeBDUXE1XxJ036J8OWSFrb3fti7Ye
cjZoAQ/PoGI7qjxJtyFQjENnWlSzB4198ZWghtTIQtcZB9qqlTcLBK++OTVFgU96
Ft8EpwLxMijCaTbWYaqyKiP4z8ZZ4ifD/upD44qkPV5hzA4nTDbO
-----END RSA PRIVATE KEY-----`;

  const apiUrl = `https://staging.sign.singpass.gov.sg/api/v3/sign-requests/${id}/signed-doc`;

  const jwt = createJWT(
    {
      exchange_code: exchange_code,
      client_id: clientId,
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
    apiRes.on("data", (chunk) => (data += chunk));
    apiRes.on("end", () => {
      try {
        if (
          apiRes.headers["content-type"] &&
          apiRes.headers["content-type"].includes("application/json")
        ) {
          const result = JSON.parse(data);
          if (apiRes.statusCode === 200) {
            res.status(200).json({ status: "signed", signed_doc_url: result.signed_doc_url });
          } else if (apiRes.statusCode === 400 && result.error === "DOCUMENT_NOT_SIGNED") {
            res.status(200).json({ status: "pending" });
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

  apiReq.end();
};

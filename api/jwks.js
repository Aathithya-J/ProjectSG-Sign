module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  if (req.method === "OPTIONS") {
    res.status(200).end();
    return;
  }

  const jwks = {
    "keys": [
      {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": "key-1",
        "x": "n0DpaD-GFo0vqReWllbLIRV2oT-I_W0KLR2a3WohKaE",
        "y": "ZO1xoT-PGqOFTy3SljpjLs8UZjuXSMIVM7C0iPqkLnQ",
        "alg": "ES256"
      }
    ]
  };

  res.status(200).json(jwks);
};

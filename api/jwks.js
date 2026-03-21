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
        "x": "1tR88zrGoPUV-Fr4bh_9NR-mDhC9rLswDp85hkbKBT0",
        "y": "1vYh1M53NK_b7l9Y-1FgCENOp6Fl9StVVLr3KqK_Ka8",
        "alg": "ES256"
      }
    ]
  };

  res.status(200).json(jwks);
};

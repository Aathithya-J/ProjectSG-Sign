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
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "key-1",
        "n": "4F0GrqNRE3SuCViY56VoOUPZ1IJPSQG8xjfAwGetbH-E4bVLh6FdcFV6giESAgc6E7xNQLVLRv2vw9zOFjNqHTbVkFhfJfiNJRyPUN_M9wqu6BxruwRZei9sD686SH5sUfFJ76TMUfU8mNROt21a8gDI0qDgNI8u966V911xnzub1n21j6bC8SyMybtRTVLt_UsjUMlbEkJ0O1F2MN567tjFL39ocgF3FhwYPx2B6_8N3ox2OjlzKluKB_sb1PXtV2DqPoB8uf7MpytwD2hF_PJkcaZF5JwZIO7-Gm4ZMrEHsyUqMspLGNbLSf87NanO-wQEzZJKKGQjGefgEKAGZQ",
        "e": "AQAB"
      }
    ]
  };

  res.status(200).json(jwks);
};

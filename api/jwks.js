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
        "n": "qV7gM-2TT2gRRix0qlhzMysgcOuM9kmx8k_k3HgJvx0-XbTr0V99LoF3f-Gcn9g_2b_KgpelqrEssCQYK1dnFsDGLWhpD7JwGmIRkYSfSOCzMm-BW83AuJU0vCkmNrr1RT5-rehba76kNPolZDJdjgYrnu0aKvzAt3uZnGHGm4L2c625Fv6BgDj32sb3Wsm06nDEjxKmDWa3DiJL1C-ZCcdvnSCITwMbMI5H5g9uYvVkRXavxtba6-l5r_SaMqVbkkYIFg0ql8QKbXK2TvAQUkIBM8fdKq2iFgmVd3H7W6FRuNRtv53ctebvpPzbhFu3istsGTGjcB89yZYHWO2w",
        "e": "AQAB"
      }
    ]
  };

  res.status(200).json(jwks);
};

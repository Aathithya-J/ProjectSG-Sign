export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  const jwks = {
    keys: [
      {
        kty: 'EC',
        crv: 'P-256',
        use: 'sig',
        alg: 'ES256',
        kid: 'key-1',
        x: 'LJnSx3j5HDMdTaKq0zYHLh53gdE9pSgaTp_I_pbQwLU',
        y: 'q9_A0aua5mpvzJwMAMkFhMlBz3llnepZEj6MrvtrDWw',
      },
    ],
  };
 
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.setHeader('Content-Type', 'application/json');
  return res.status(200).json(jwks);
}
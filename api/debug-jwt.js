// api/debug-jwt.js
// TEMPORARY — delete after debugging. Shows exactly what JWT is being built.
const crypto = require('crypto');

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

module.exports = function handler(req, res) {
  const rawPem = process.env.SINGPASS_PRIVATE_KEY_PEM;
  const clientId = process.env.SINGPASS_CLIENT_ID;
  const kid = process.env.SINGPASS_KID;

  // 1. Check env vars are present
  const envCheck = {
    SINGPASS_CLIENT_ID: clientId ? `✅ "${clientId}"` : '❌ MISSING',
    SINGPASS_KID: kid ? `✅ "${kid}"` : '❌ MISSING',
    SINGPASS_PRIVATE_KEY_PEM: rawPem
      ? `✅ present (${rawPem.length} chars, starts with: ${rawPem.slice(0, 40)}...)`
      : '❌ MISSING',
  };

  if (!rawPem || !clientId || !kid) {
    return res.status(200).json({ envCheck, error: 'Missing env vars' });
  }

  // 2. Fix newlines
  const pem = rawPem.replace(/\\n/g, '\n');
  const pemLines = pem.split('\n');

  // 3. Try loading the key
  let keyInfo, pubJwk, sigTest;
  try {
    const privKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
    const pubKey  = crypto.createPublicKey(privKey);
    pubJwk = pubKey.export({ format: 'jwk' });
    keyInfo = `✅ Key loaded OK — curve: ${pubJwk.crv}`;

    // 4. Build a test JWT
    const header  = base64url(Buffer.from(JSON.stringify({ alg: 'ES256', kid })));
    const payload = base64url(Buffer.from(JSON.stringify({
      client_id: clientId,
      doc_name: 'test.pdf',
      x: 0.5, y: 0.1, page: 1,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    })));
    const signingInput = `${header}.${payload}`;
    const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), {
      key: privKey,
      dsaEncoding: 'ieee-p1363',
    });
    const jwt = `${signingInput}.${base64url(sigBuf)}`;

    // Decode back to verify
    const [h, p] = jwt.split('.');
    sigTest = {
      header:  JSON.parse(Buffer.from(h, 'base64url').toString()),
      payload: JSON.parse(Buffer.from(p, 'base64url').toString()),
      sigBytes: sigBuf.length,
      jwtPreview: jwt.slice(0, 80) + '...',
    };
  } catch (err) {
    keyInfo = `❌ Key load failed: ${err.message}`;
  }

  return res.status(200).json({
    envCheck,
    pemFirstLine: pemLines[0],
    pemLastLine:  pemLines[pemLines.length - 2],
    pemLineCount: pemLines.length,
    keyInfo,
    publicKeyInJWKS: pubJwk ? { x: pubJwk.x, y: pubJwk.y } : null,
    jwksEndpointHas: { x: 'LJnSx3j5HDMdTaKq0zYHLh53gdE9pSgaTp_I_pbQwLU', y: 'q9_A0aua5mpvzJwMAMkFhMlBz3llnepZEj6MrvtrDWw' },
    keysMatch: pubJwk
      ? (pubJwk.x === 'LJnSx3j5HDMdTaKq0zYHLh53gdE9pSgaTp_I_pbQwLU' && pubJwk.y === 'q9_A0aua5mpvzJwMAMkFhMlBz3llnepZEj6MrvtrDWw'
          ? '✅ Private key MATCHES the public key in /api/jwks'
          : '❌ MISMATCH — private key does not match /api/jwks public key!')
      : 'unknown',
    sigTest,
  });
};
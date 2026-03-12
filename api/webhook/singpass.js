// api/webhook/singpass.js
const crypto = require('crypto');

// In-memory store — swap for DB/KV in production
const store = globalThis.__singpassStore ??= new Map();

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks).toString('utf8');

    console.log('Webhook received:', rawBody.slice(0, 500));

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      payload = { raw: rawBody };
    }

    const { sign_request_id, signed_doc_url, signer_info } = payload;

    if (sign_request_id) {
      store.set(sign_request_id, {
        signed_doc_url: signed_doc_url ?? null,
        signer_info: signer_info ?? null,
        received_at: new Date().toISOString(),
      });
      console.log(`Stored result for ${sign_request_id}`);
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('webhook error:', err);
    return res.status(500).json({ error: err.message });
  }
};

module.exports.config = { api: { bodyParser: false } };
module.exports.store = store;
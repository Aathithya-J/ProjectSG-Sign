module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method === 'POST') {
    console.log('Singpass Webhook Received:', JSON.stringify(req.body, null, 2));
    return res.status(200).send('OK');
  }

  res.status(405).send('Method Not Allowed');
};

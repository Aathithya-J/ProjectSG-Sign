# Singpass Sign – Vercel Deployment

## Files
```
index.html        ← frontend (upload PDF, show signing link, poll for result)
api/sign.py       ← single Python serverless function (handles all /api/* routes)
vercel.json       ← routing config
requirements.txt  ← PyJWT + cryptography
```

## Deploy to Vercel

```bash
npm i -g vercel
vercel deploy
```

## Environment Variables

Set these in Vercel dashboard → Project → Settings → Environment Variables:

| Variable | Description |
|---|---|
| `SINGPASS_CLIENT_ID` | Your RP client ID from Singpass onboarding |
| `SINGPASS_PRIVATE_KEY_PEM` | Your private key PEM (replace newlines with `\n`) |
| `SINGPASS_KID` | Key ID matching your JWKS endpoint |
| `WEBHOOK_BASE_URL` | Your Vercel deployment URL, e.g. `https://yourapp.vercel.app` |

## Onboarding Steps (required before this works)

1. Submit form at https://go.gov.sg/sign-onboarding
2. Generate a keypair → host public key as JWKS at `/api/jwks` (see Singpass docs)
3. Set your webhook URL as `https://yourapp.vercel.app/api/webhook`
4. Set your redirect URL as `https://yourapp.vercel.app`
5. Receive staging credentials → fill in env vars above

## Flow

```
[You] Upload PDF on index.html
      ↓
POST /api/sign  (serverless fn)
      ↓
Singpass Sign API  →  returns signing_url + sign_request_id
      ↓
[You] Share signing_url with client (opens Sign portal)
      ↓
[Client] Scans QR with Singpass app → signs document
      ↓
Singpass → POST /api/webhook  (notifies completion)
      ↓
GET /api/status  (frontend polls every 5s)
      ↓
Returns signed_doc_url → download button appears
```

## Signature Placement

The current config places one signature at bottom-right of page 1.
To add signatures to every page, duplicate the `sign_locations` array entry with different page numbers (up to 20 locations supported in V3).

Use the **Sign Location Helper** tool to visually pick coordinates:
https://docs.sign.singpass.gov.sg → API Docs → Sign V3

## Important Notes

- Signing sessions expire in **30 minutes** — only initiate when client is ready to sign
- In-memory `_store` dict is reset on each cold start. For production, swap for Vercel KV or Redis
- Always verify the Singpass webhook JWT signature in production (see JWKS Specification docs)

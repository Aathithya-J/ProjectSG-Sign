"""
api/jwks.py  –  Vercel Serverless Function
Serves your public key as a JWKS document.
Singpass calls this to verify your JWT auth tokens.
"""

import json
import os
from http.server import BaseHTTPRequestHandler

{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "htxdUAiHlysBzyvdSzdb-iuwM7ni1AaO5Bc__VdBQBs",
      "y": "dN4JkHBS_alScY2q_dJh2uM08AFpMKPq2wbNKDQsJIY",
      "kid": "a90580b7-34e8-4e4d-ab6a-03bd26249c7c",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Allow overriding via env var for easy key rotation without redeploying
        jwks_env = os.environ.get("SINGPASS_JWKS_JSON", "")
        if jwks_env:
            try:
                jwks = json.loads(jwks_env)
            except Exception:
                jwks = JWKS_DATA
        else:
            jwks = JWKS_DATA

        body = json.dumps(jwks).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
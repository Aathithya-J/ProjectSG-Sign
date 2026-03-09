import json
import os
from http.server import BaseHTTPRequestHandler

JWKS_DATA = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "key-1",
            "n": "qV7gM-2TT2gRRix0qlhzMysgcOuM9kmx8k_k3HgJvx0-XbTr0V99LoF3f-Gcn9g_2b_KgpelqrEssCQYK1dnFsDGLWhpD7JwGmIRkYSfSOCzMm-BW83AuJU0vCkmNrr1RT5-rehba76kNPolZDJdjgYrnu0aKvzAt3uZnGHGm4L2c625Fv6BgDj32sb3Wsm06nDEjxKmDWa3DiJL1C-ZCcdvnSCITwMbMI5H5g9uYvVkRXavxtba6-l5r_SaMqVbkkYIFg0ql8QKbXK2TvAQUkIBM8fdKq2iFgmVd3H7W6FRuNRtv53ctebvpPzbhFu3ykLkKsGTGjcB89yZYHWO2w",
            "e": "AQAB"
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
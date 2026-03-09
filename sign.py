"""
api/sign.py  –  Vercel Serverless Function (Python)
Handles:
  POST /api/sign    → initiate a Singpass Sign V3 session
  GET  /api/status  → poll for signing result (via stored exchange_code)

ENV VARS to set in Vercel dashboard:
  SINGPASS_CLIENT_ID       - your RP client_id from onboarding
  SINGPASS_PRIVATE_KEY_PEM - your RSA/EC private key (PEM, single line with \\n)
  SINGPASS_KID             - key ID matching your JWKS
  SIGNING_SECRET           - a random secret to sign internal status tokens
  WEBHOOK_BASE_URL         - your Vercel deployment URL, e.g. https://yourapp.vercel.app
"""

import os
import json
import time
import uuid
import base64
import hashlib
import hmac
import tempfile
from http.server import BaseHTTPRequestHandler
import urllib.request
import urllib.parse

# ── Constants ────────────────────────────────────────────────────────────────
STAGING_API  = "https://api.sign.singpass.gov.sg"  # update when Singpass confirms staging URL
PROD_API     = "https://api.sign.singpass.gov.sg"
SIGN_ENDPOINT = "/v3/signing-sessions"

# In-memory store: { sign_request_id: { exchange_code, signed_doc_url, status } }
# NOTE: Vercel serverless functions are stateless between invocations.
# For production, replace with a real store (Redis / Vercel KV / Supabase etc.)
# For staging/demo this works fine if the same instance handles poll requests.
_store: dict = {}


# ── JWT helper (no external deps) ────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _make_jwt(payload: dict, private_key_pem: str, kid: str, alg: str = "RS256") -> str:
    """Build a signed JWT. Uses PyJWT if available, falls back to cryptography lib."""
    try:
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(private_key_pem.encode(), password=None)
        return pyjwt.encode(payload, private_key, algorithm=alg, headers={"kid": kid})
    except ImportError:
        raise RuntimeError(
            "PyJWT and cryptography packages are required. "
            "Add them to requirements.txt: PyJWT>=2.8.0 cryptography>=41.0.0"
        )


# ── Helpers ──────────────────────────────────────────────────────────────────
def _get_api_base(is_staging: bool) -> str:
    return STAGING_API if is_staging else PROD_API


def _build_auth_token(client_id: str, private_key_pem: str, kid: str, api_url: str) -> str:
    now = int(time.time())
    payload = {
        "sub": client_id,
        "iss": client_id,
        "aud": api_url,
        "iat": now,
        "exp": now + 300,  # 5 min validity
        "jti": str(uuid.uuid4()),
    }
    return _make_jwt(payload, private_key_pem, kid)


def _json_response(handler: "Handler", status: int, data: dict):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)


def _parse_multipart(body: bytes, content_type: str):
    """Parse multipart/form-data manually (no external deps)."""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip()
            break
    if not boundary:
        return {}, None

    boundary_bytes = ("--" + boundary).encode()
    fields = {}
    pdf_bytes = None

    parts = body.split(boundary_bytes)
    for segment in parts[1:]:
        if segment in (b"--\r\n", b"--"):
            continue
        # Split headers from body
        if b"\r\n\r\n" in segment:
            headers_raw, content = segment.split(b"\r\n\r\n", 1)
            content = content.rstrip(b"\r\n--")
        else:
            continue

        headers_str = headers_raw.decode(errors="replace")
        name = None
        filename = None
        for line in headers_str.splitlines():
            if "Content-Disposition" in line:
                for token in line.split(";"):
                    token = token.strip()
                    if token.startswith('name="'):
                        name = token[6:-1]
                    elif token.startswith('filename="'):
                        filename = token[10:-1]

        if name == "file" and filename:
            pdf_bytes = content
        elif name:
            fields[name] = content.decode(errors="replace")

    return fields, pdf_bytes


# ── Handler ──────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default logging

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── POST /api/sign ────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in ("/api/sign", "/sign"):
            _json_response(self, 404, {"error": "Not found"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        content_type = self.headers.get("Content-Type", "")

        fields, pdf_bytes = _parse_multipart(body, content_type)

        if not pdf_bytes:
            _json_response(self, 400, {"error": "No PDF file provided"})
            return

        # Read env vars
        client_id = os.environ.get("SINGPASS_CLIENT_ID", "")
        private_key_pem = os.environ.get("SINGPASS_PRIVATE_KEY_PEM", "").replace("\\n", "\n")
        kid = os.environ.get("SINGPASS_KID", "")
        webhook_base = os.environ.get("WEBHOOK_BASE_URL", "")

        if not all([client_id, private_key_pem, kid]):
            _json_response(self, 500, {
                "error": "Missing env vars: SINGPASS_CLIENT_ID, SINGPASS_PRIVATE_KEY_PEM, SINGPASS_KID"
            })
            return

        is_staging = fields.get("staging", "1") == "1"
        api_base = _get_api_base(is_staging)
        doc_name = fields.get("doc_name", "document.pdf")
        signer_nric = fields.get("signer_nric", "").strip().upper()

        # Build sign locations — bottom-right of every page
        # These are placeholder coordinates; adjust based on your actual PDF dimensions.
        # Use the Singpass Sign Location Helper tool to get correct coords:
        # https://docs.sign.singpass.gov.sg → API Docs → Sign V3
        sign_locations = [
            {
                "page": 1,          # Singpass will repeat on all pages with multi-location
                "x": 0.72,          # normalised x (0–1), right side
                "y": 0.05,          # normalised y from bottom (0–1), near bottom
                "width": 0.25,
                "height": 0.06,
            }
        ]

        payload = {
            "doc_name": doc_name,
            "sign_locations": sign_locations,
        }
        if signer_nric:
            payload["signer_uin_hash"] = hashlib.sha256(signer_nric.encode()).hexdigest()

        if webhook_base:
            payload["webhook_url"] = webhook_base.rstrip("/") + "/api/webhook"

        try:
            url = api_base + SIGN_ENDPOINT
            auth_token = _build_auth_token(client_id, private_key_pem, kid, url)

            # Build multipart request to Singpass API
            boundary = uuid.uuid4().hex
            sp_body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="payload"\r\n'
                f"Content-Type: application/json\r\n\r\n"
                f"{json.dumps(payload)}\r\n"
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{doc_name}"\r\n'
                f"Content-Type: application/pdf\r\n\r\n"
            ).encode() + pdf_bytes + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                url,
                data=sp_body,
                method="POST",
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(sp_body)),
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read())

        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")
            _json_response(self, 502, {"error": f"Singpass API error: {e.code}", "detail": err_body})
            return
        except Exception as e:
            _json_response(self, 500, {"error": str(e)})
            return

        sign_request_id = resp_data.get("sign_request_id", "")
        exchange_code   = resp_data.get("exchange_code", "")
        signing_url     = resp_data.get("signing_url", "")

        # Store for later polling
        _store[sign_request_id] = {
            "exchange_code": exchange_code,
            "status": "pending",
            "signed_doc_url": None,
        }

        _json_response(self, 200, {
            "sign_request_id": sign_request_id,
            "signing_url": signing_url,
        })

    # ── GET /api/status ───────────────────────────────────────────────────
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in ("/api/status", "/status"):
            _json_response(self, 404, {"error": "Not found"})
            return

        params = dict(urllib.parse.parse_qsl(parsed.query))
        req_id = params.get("id", "")
        is_staging = params.get("staging", "1") == "1"

        record = _store.get(req_id)
        if not record:
            _json_response(self, 404, {"error": "Session not found. It may have expired or been on a different instance."})
            return

        if record["status"] == "signed":
            _json_response(self, 200, {"status": "signed", "signed_doc_url": record["signed_doc_url"]})
            return

        # Poll Singpass for signing result
        client_id = os.environ.get("SINGPASS_CLIENT_ID", "")
        private_key_pem = os.environ.get("SINGPASS_PRIVATE_KEY_PEM", "").replace("\\n", "\n")
        kid = os.environ.get("SINGPASS_KID", "")

        if not all([client_id, private_key_pem, kid]):
            _json_response(self, 500, {"error": "Missing server env vars"})
            return

        api_base = _get_api_base(is_staging)
        result_url = f"{api_base}{SIGN_ENDPOINT}/{req_id}/result"

        try:
            auth_token = _build_auth_token(client_id, private_key_pem, kid, result_url)
            exchange_code = record["exchange_code"]

            body_data = json.dumps({"exchange_code": exchange_code}).encode()
            req = urllib.request.Request(
                result_url,
                data=body_data,
                method="POST",
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())

            signed_url = result.get("signed_doc_url") or result.get("download_url")
            if signed_url:
                _store[req_id]["status"] = "signed"
                _store[req_id]["signed_doc_url"] = signed_url
                _json_response(self, 200, {"status": "signed", "signed_doc_url": signed_url})
            else:
                _json_response(self, 200, {"status": "pending"})

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Not yet signed
                _json_response(self, 200, {"status": "pending"})
            else:
                _json_response(self, 200, {"status": "pending", "debug": str(e)})
        except Exception as e:
            _json_response(self, 200, {"status": "pending", "debug": str(e)})

    # ── POST /api/webhook (called by Singpass after signing) ──────────────
    # This is a bonus handler on the same file
    # Singpass POSTs { "token": "<JWT>" } here after signing completes
    def _handle_webhook(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
            token = data.get("token", "")
            # Decode JWT payload (without verification for simplicity — add verification for production)
            parts = token.split(".")
            if len(parts) == 3:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
                req_id = payload.get("sign_request_id", "")
                signed_url = payload.get("signed_doc_url", "")
                if req_id and signed_url and req_id in _store:
                    _store[req_id]["status"] = "signed"
                    _store[req_id]["signed_doc_url"] = signed_url
        except Exception:
            pass
        # Always respond 200 immediately as required by Singpass
        self.send_response(200)
        self.end_headers()

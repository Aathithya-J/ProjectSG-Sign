"""Shared utilities for all Singpass Sign API handlers."""
import os, json, time, uuid, base64
from http.server import BaseHTTPRequestHandler

STAGING_API   = "https://stg-api.sign.singpass.gov.sg"
PROD_API      = "https://api.sign.singpass.gov.sg"
SIGN_ENDPOINT = "/v3/signing-sessions"

# In-memory store — shared within the same Vercel function instance
# For production replace with Vercel KV / Redis
_store: dict = {}


def get_api_base(is_staging: bool) -> str:
    return STAGING_API if is_staging else PROD_API

def make_jwt(payload: dict, private_key_pem: str, kid: str) -> str:
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    private_key = load_pem_private_key(private_key_pem.encode(), password=None)
    return pyjwt.encode(payload, private_key, algorithm="ES256", headers={"kid": kid})  # ← RS256 → ES256

def build_auth_token(client_id: str, private_key_pem: str, kid: str, audience: str) -> str:
    now = int(time.time())
    return make_jwt({
        "sub": client_id, "iss": client_id, "aud": audience,
        "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()),
    }, private_key_pem, kid)


def json_response(handler: BaseHTTPRequestHandler, status: int, data: dict):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def parse_multipart(body: bytes, content_type: str):
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip()
            break
    if not boundary:
        return {}, None

    fields, pdf_bytes = {}, None
    for segment in body.split(("--" + boundary).encode())[1:]:
        if segment in (b"--\r\n", b"--"):
            continue
        if b"\r\n\r\n" not in segment:
            continue
        headers_raw, content = segment.split(b"\r\n\r\n", 1)
        content = content.rstrip(b"\r\n--")
        name = filename = None
        for line in headers_raw.decode(errors="replace").splitlines():
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


def get_env():
    return (
        os.environ.get("SINGPASS_CLIENT_ID", ""),
        os.environ.get("SINGPASS_PRIVATE_KEY_PEM", "").replace("\\n", "\n"),
        os.environ.get("SINGPASS_KID", ""),
        os.environ.get("WEBHOOK_BASE_URL", ""),
    )

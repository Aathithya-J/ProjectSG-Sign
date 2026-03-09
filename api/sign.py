import os, json, uuid, hashlib, time, base64, ssl, tempfile, subprocess
import http.client, urllib.parse
from http.server import BaseHTTPRequestHandler

STAGING_API   = "https://stg-api.sign.singpass.gov.sg"
PROD_API      = "https://api.sign.singpass.gov.sg"
SIGN_ENDPOINT = "/v3/signing-sessions"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(payload: dict, pem: str, kid: str) -> str:
    """
    RS256 JWT via `openssl dgst` subprocess — avoids loading the
    cryptography/OpenSSL Python C-extension in the same process as the
    outbound HTTPS call, which causes [Errno 16] on Vercel.
    """
    header  = _b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    body    = _b64url(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
        kf.write(pem.encode())
        key_path = kf.name
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=message, capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"openssl sign failed: {result.stderr.decode()}")
        sig = _b64url(result.stdout)
    finally:
        os.unlink(key_path)

    return f"{header}.{body}.{sig}"


def _auth_token(client_id: str, pem: str, kid: str, audience: str) -> str:
    now = int(time.time())
    return _make_jwt({
        "sub": client_id, "iss": client_id, "aud": audience,
        "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()),
    }, pem, kid)


def _respond(handler, status, data):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.end_headers()
    handler.wfile.write(body)


def _parse_multipart(body, content_type):
    boundary = None
    for p in content_type.split(";"):
        p = p.strip()
        if p.startswith("boundary="):
            boundary = p[9:].strip()
    if not boundary:
        return {}, None
    fields, pdf = {}, None
    for seg in body.split(("--" + boundary).encode())[1:]:
        if seg in (b"--\r\n", b"--"):
            continue
        if b"\r\n\r\n" not in seg:
            continue
        hdr, content = seg.split(b"\r\n\r\n", 1)
        content = content.rstrip(b"\r\n--")
        name = filename = None
        for line in hdr.decode(errors="replace").splitlines():
            if "Content-Disposition" in line:
                for tok in line.split(";"):
                    tok = tok.strip()
                    if tok.startswith('name="'):
                        name = tok[6:-1]
                    if tok.startswith('filename="'):
                        filename = tok[10:-1]
        if name == "file" and filename:
            pdf = content
        elif name:
            fields[name] = content.decode(errors="replace")
    return fields, pdf


def _https_post(url: str, body: bytes, headers: dict) -> tuple:
    """One-shot HTTPS POST — fresh connection and SSL context every time."""
    parsed = urllib.parse.urlparse(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED
    conn = http.client.HTTPSConnection(parsed.netloc, timeout=30, context=ctx)
    try:
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):

    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        client_id    = os.environ.get("SINGPASS_CLIENT_ID", "")
        pem          = os.environ.get("SINGPASS_PRIVATE_KEY_PEM", "").replace("\\n", "\n")
        kid          = os.environ.get("SINGPASS_KID", "")
        webhook_base = os.environ.get("WEBHOOK_BASE_URL", "")

        if not all([client_id, pem, kid]):
            missing = [k for k, v in {
                "SINGPASS_CLIENT_ID": client_id,
                "SINGPASS_PRIVATE_KEY_PEM": pem,
                "SINGPASS_KID": kid,
            }.items() if not v]
            _respond(self, 500, {"error": "Missing env vars", "missing": missing})
            return

        length      = int(self.headers.get("Content-Length", 0))
        body        = self.rfile.read(length)
        fields, pdf = _parse_multipart(body, self.headers.get("Content-Type", ""))

        if not pdf:
            _respond(self, 400, {"error": "No PDF provided"})
            return

        is_staging  = fields.get("staging", "1") == "1"
        doc_name    = fields.get("doc_name", "document.pdf")
        signer_nric = fields.get("signer_nric", "").strip().upper()
        api_base    = STAGING_API if is_staging else PROD_API

        sp_payload = {
            "doc_name": doc_name,
            "sign_locations": [
                {"page": i, "x": 0.72, "y": 0.05, "width": 0.25, "height": 0.06}
                for i in range(1, 21)
            ],
        }
        if signer_nric:
            sp_payload["signer_uin_hash"] = hashlib.sha256(signer_nric.encode()).hexdigest()
        if webhook_base:
            sp_payload["webhook_url"] = webhook_base.rstrip("/") + "/api/webhook/singpass"

        try:
            url = api_base + SIGN_ENDPOINT

            # Step 1 — build JWT using openssl subprocess (no Python crypto bindings)
            token = _auth_token(client_id, pem, kid, url)

            # Step 2 — POST to Singpass (stdlib SSL only, no cryptography package)
            boundary = uuid.uuid4().hex
            sp_body = (
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"payload\"\r\n"
                f"Content-Type: application/json\r\n\r\n"
                f"{json.dumps(sp_payload)}\r\n"
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{doc_name}\"\r\n"
                f"Content-Type: application/pdf\r\n\r\n"
            ).encode() + pdf + f"\r\n--{boundary}--\r\n".encode()

            status, raw = _https_post(url, sp_body, {
                "Authorization":  f"Bearer {token}",
                "Content-Type":   f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(sp_body)),
            })

            if status >= 400:
                _respond(self, 502, {
                    "error":  f"Singpass API {status}",
                    "detail": raw.decode(errors="replace"),
                })
                return

            data = json.loads(raw)

        except Exception as e:
            _respond(self, 500, {"error": str(e)})
            return

        _respond(self, 200, {
            "sign_request_id": data.get("sign_request_id", ""),
            "signing_url":     data.get("signing_url", ""),
        })
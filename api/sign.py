import os, json, uuid, hashlib, time, base64, ssl
import http.client, urllib.parse
from http.server import BaseHTTPRequestHandler

STAGING_API   = "https://stg-api.sign.singpass.gov.sg"
PROD_API      = "https://api.sign.singpass.gov.sg"
SIGN_ENDPOINT = "/v3/signing-sessions"


# ── Pure-stdlib RSA PKCS#1 v1.5 SHA-256 ──────────────────────────────────
# No cryptography package, no C-extensions, no /dev/urandom dependency.

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _parse_der_length(data, pos):
    b = data[pos]; pos += 1
    if b & 0x80:
        n = b & 0x7f
        length = int.from_bytes(data[pos:pos+n], "big"); pos += n
    else:
        length = b
    return length, pos

def _parse_der_int(data, pos):
    assert data[pos] == 0x02, f"Expected INTEGER at {pos}"
    pos += 1
    length, pos = _parse_der_length(data, pos)
    value = int.from_bytes(data[pos:pos+length], "big")
    return value, pos + length

def _load_rsa_key(pem: str):
    """Parse PKCS#1 or PKCS#8 RSA PEM, return (n, d)."""
    lines = [l.strip() for l in pem.strip().splitlines()]
    der   = base64.b64decode("".join(l for l in lines if not l.startswith("-----")))
    pos   = 0
    assert der[pos] == 0x30; pos += 1
    _, pos = _parse_der_length(der, pos)
    if der[pos] == 0x30:                        # PKCS#8
        pos += 1
        seq_len, pos = _parse_der_length(der, pos)
        pos += seq_len
        assert der[pos] == 0x04; pos += 1
        _, pos = _parse_der_length(der, pos)
        assert der[pos] == 0x30; pos += 1
        _, pos = _parse_der_length(der, pos)
    _, pos  = _parse_der_int(der, pos)          # version
    n, pos  = _parse_der_int(der, pos)
    _e, pos = _parse_der_int(der, pos)
    d, pos  = _parse_der_int(der, pos)
    return n, d

def _rsa_sign(message: bytes, pem: str) -> bytes:
    n, d = _load_rsa_key(pem)
    k    = (n.bit_length() + 7) // 8
    # SHA-256 DigestInfo prefix (RFC 3447)
    prefix = bytes([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
                    0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20])
    T      = prefix + hashlib.sha256(message).digest()
    pad    = k - len(T) - 3
    assert pad >= 8
    em = b"\x00\x01" + b"\xff" * pad + b"\x00" + T
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")

def _make_jwt(payload: dict, pem: str, kid: str) -> str:
    h = _b64url(json.dumps({"alg":"RS256","typ":"JWT","kid":kid}).encode())
    b = _b64url(json.dumps(payload).encode())
    return f"{h}.{b}.{_b64url(_rsa_sign(f'{h}.{b}'.encode(), pem))}"

def _auth_token(client_id, pem, kid, audience):
    now = int(time.time())
    return _make_jwt({"sub":client_id,"iss":client_id,"aud":audience,
                      "iat":now,"exp":now+300,"jti":str(uuid.uuid4())}, pem, kid)


# ── HTTP helpers ──────────────────────────────────────────────────────────

def _respond(handler, status, data):
    body = json.dumps(data).encode()
    handler.send_response(status)
    handler.send_header("Content-Type","application/json")
    handler.send_header("Content-Length",str(len(body)))
    handler.send_header("Access-Control-Allow-Origin","*")
    handler.send_header("Access-Control-Allow-Methods","POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers","Content-Type")
    handler.end_headers()
    handler.wfile.write(body)

def _parse_multipart(body, content_type):
    boundary = None
    for p in content_type.split(";"):
        p = p.strip()
        if p.startswith("boundary="): boundary = p[9:].strip()
    if not boundary: return {}, None
    fields, pdf = {}, None
    for seg in body.split(("--"+boundary).encode())[1:]:
        if seg in (b"--\r\n",b"--"): continue
        if b"\r\n\r\n" not in seg: continue
        hdr, content = seg.split(b"\r\n\r\n",1)
        content = content.rstrip(b"\r\n--")
        name = filename = None
        for line in hdr.decode(errors="replace").splitlines():
            if "Content-Disposition" in line:
                for tok in line.split(";"):
                    tok = tok.strip()
                    if tok.startswith('name="'):    name     = tok[6:-1]
                    if tok.startswith('filename="'): filename = tok[10:-1]
        if name=="file" and filename: pdf = content
        elif name: fields[name] = content.decode(errors="replace")
    return fields, pdf

def _post(url, body, headers):
    p    = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(p.netloc, timeout=30,
                                       context=ssl.create_default_context())
    try:
        conn.request("POST", p.path or "/", body=body, headers=headers)
        r = conn.getresponse(); return r.status, r.read()
    finally:
        conn.close()


# ── Vercel handler ────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, *a): pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.end_headers()

    def do_POST(self):
        client_id    = os.environ.get("SINGPASS_CLIENT_ID","")
        pem          = os.environ.get("SINGPASS_PRIVATE_KEY_PEM","").replace("\\n","\n")
        kid          = os.environ.get("SINGPASS_KID","")
        webhook_base = os.environ.get("WEBHOOK_BASE_URL","")

        if not all([client_id,pem,kid]):
            missing = [k for k,v in {"SINGPASS_CLIENT_ID":client_id,
                "SINGPASS_PRIVATE_KEY_PEM":pem,"SINGPASS_KID":kid}.items() if not v]
            _respond(self,500,{"error":"Missing env vars","missing":missing}); return

        length      = int(self.headers.get("Content-Length",0))
        raw         = self.rfile.read(length)
        fields, pdf = _parse_multipart(raw, self.headers.get("Content-Type",""))

        if not pdf:
            _respond(self,400,{"error":"No PDF provided"}); return

        is_staging  = fields.get("staging","1")=="1"
        doc_name    = fields.get("doc_name","document.pdf")
        signer_nric = fields.get("signer_nric","").strip().upper()
        api_base    = STAGING_API if is_staging else PROD_API

        sp_payload = {"doc_name":doc_name,"sign_locations":[
            {"page":i,"x":0.72,"y":0.05,"width":0.25,"height":0.06}
            for i in range(1,21)]}
        if signer_nric:
            sp_payload["signer_uin_hash"] = hashlib.sha256(signer_nric.encode()).hexdigest()
        if webhook_base:
            sp_payload["webhook_url"] = webhook_base.rstrip("/")+"/api/webhook/singpass"

        try:
            url      = api_base+SIGN_ENDPOINT
            token    = _auth_token(client_id, pem, kid, url)
            bnd      = uuid.uuid4().hex
            sp_body  = (
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"payload\"\r\n"
                f"Content-Type: application/json\r\n\r\n{json.dumps(sp_payload)}\r\n"
                f"--{bnd}\r\nContent-Disposition: form-data; name=\"file\"; "
                f"filename=\"{doc_name}\"\r\nContent-Type: application/pdf\r\n\r\n"
            ).encode() + pdf + f"\r\n--{bnd}--\r\n".encode()

            status, resp = _post(url, sp_body, {
                "Authorization":  f"Bearer {token}",
                "Content-Type":   f"multipart/form-data; boundary={bnd}",
                "Content-Length": str(len(sp_body)),
            })
            if status >= 400:
                _respond(self,502,{"error":f"Singpass API {status}",
                                   "detail":resp.decode(errors="replace")}); return
            data = json.loads(resp)

        except Exception as e:
            _respond(self,500,{"error":str(e)}); return

        _respond(self,200,{"sign_request_id":data.get("sign_request_id",""),
                           "signing_url":data.get("signing_url","")})
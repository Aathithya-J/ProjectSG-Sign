import os, json, uuid, hashlib, time, base64, ssl
import http.client, urllib.parse
from http.server import BaseHTTPRequestHandler

STAGING_API   = "https://stg-api.sign.singpass.gov.sg"
PROD_API      = "https://api.sign.singpass.gov.sg"
SIGN_ENDPOINT = "/v3/signing-sessions"

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _make_jwt(payload, pem, kid):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    header  = _b64url(json.dumps({"alg":"RS256","typ":"JWT","kid":kid}).encode())
    body    = _b64url(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()
    key     = load_pem_private_key(pem.encode(), password=None)
    sig     = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{body}.{_b64url(sig)}"

def _auth_token(client_id, pem, kid, audience):
    now = int(time.time())
    return _make_jwt({"sub":client_id,"iss":client_id,"aud":audience,"iat":now,"exp":now+300,"jti":str(uuid.uuid4())}, pem, kid)

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
                    if tok.startswith('name="'): name = tok[6:-1]
                    if tok.startswith('filename="'): filename = tok[10:-1]
        if name=="file" and filename: pdf = content
        elif name: fields[name] = content.decode(errors="replace")
    return fields, pdf

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
            _respond(self,500,{"error":"Missing env vars","missing":[k for k,v in {"SINGPASS_CLIENT_ID":client_id,"SINGPASS_PRIVATE_KEY_PEM":pem,"SINGPASS_KID":kid}.items() if not v]})
            return
        length = int(self.headers.get("Content-Length",0))
        body   = self.rfile.read(length)
        fields, pdf = _parse_multipart(body, self.headers.get("Content-Type",""))
        if not pdf:
            _respond(self,400,{"error":"No PDF provided"})
            return
        is_staging  = fields.get("staging","1")=="1"
        doc_name    = fields.get("doc_name","document.pdf")
        signer_nric = fields.get("signer_nric","").strip().upper()
        api_base    = STAGING_API if is_staging else PROD_API
        payload = {"doc_name":doc_name,"sign_locations":[{"page":i,"x":0.72,"y":0.05,"width":0.25,"height":0.06} for i in range(1,21)]}
        if signer_nric: payload["signer_uin_hash"] = hashlib.sha256(signer_nric.encode()).hexdigest()
        if webhook_base: payload["webhook_url"] = webhook_base.rstrip("/")+"/api/webhook/singpass"
        try:
            url      = api_base+SIGN_ENDPOINT
            token    = _auth_token(client_id,pem,kid,url)
            boundary = uuid.uuid4().hex
            sp_body  = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"payload\"\r\nContent-Type: application/json\r\n\r\n{json.dumps(payload)}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{doc_name}\"\r\nContent-Type: application/pdf\r\n\r\n").encode()+pdf+f"\r\n--{boundary}--\r\n".encode()

            parsed   = urllib.parse.urlparse(url)
            ctx      = ssl.create_default_context()
            conn     = http.client.HTTPSConnection(parsed.netloc, timeout=30, context=ctx)
            try:
                conn.request("POST", parsed.path, body=sp_body, headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type":  f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(sp_body)),
                })
                resp = conn.getresponse()
                raw  = resp.read()
                if resp.status >= 400:
                    _respond(self, 502, {"error": f"Singpass API {resp.status}", "detail": raw.decode(errors="replace")})
                    return
                data = json.loads(raw)
            finally:
                conn.close()
        except http.client.HTTPException as e:
            _respond(self,502,{"error":f"HTTP error: {str(e)}"})
            return
        except Exception as e:
            _respond(self,500,{"error":str(e)})
            return
        _respond(self,200,{"sign_request_id":data.get("sign_request_id",""),"signing_url":data.get("signing_url","")})
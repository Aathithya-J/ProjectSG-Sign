"""
api/sign.py — POST /api/sign
Receives a PDF, creates a Singpass Sign V3 session, returns signing_url.
"""
import json, uuid, hashlib, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler
from api._shared import (
    get_api_base, build_auth_token, json_response,
    parse_multipart, get_env, SIGN_ENDPOINT, _store
)


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args): pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        client_id, private_key_pem, kid, webhook_base = get_env()
        if not all([client_id, private_key_pem, kid]):
            json_response(self, 500, {"error": "Missing env vars: SINGPASS_CLIENT_ID, SINGPASS_PRIVATE_KEY_PEM, SINGPASS_KID"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        fields, pdf_bytes = parse_multipart(body, self.headers.get("Content-Type", ""))

        if not pdf_bytes:
            json_response(self, 400, {"error": "No PDF file provided"})
            return

        is_staging  = fields.get("staging", "1") == "1"
        doc_name    = fields.get("doc_name", "document.pdf")
        signer_nric = fields.get("signer_nric", "").strip().upper()
        api_base    = get_api_base(is_staging)

        payload = {
            "doc_name": doc_name,
            "sign_locations": [
                {"page": i, "x": 0.72, "y": 0.05, "width": 0.25, "height": 0.06}
                for i in range(1, 21)
            ],
        }
        if signer_nric:
            payload["signer_uin_hash"] = hashlib.sha256(signer_nric.encode()).hexdigest()
        if webhook_base:
            payload["webhook_url"] = webhook_base.rstrip("/") + "/api/webhook/singpass"

        try:
            url        = api_base + SIGN_ENDPOINT
            auth_token = build_auth_token(client_id, private_key_pem, kid, url)
            boundary   = uuid.uuid4().hex

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
                url, data=sp_body, method="POST",
                headers={
                    "Authorization":  f"Bearer {auth_token}",
                    "Content-Type":   f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(sp_body)),
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read())

        except urllib.error.HTTPError as e:
            json_response(self, 502, {"error": f"Singpass API {e.code}", "detail": e.read().decode(errors="replace")})
            return
        except Exception as e:
            json_response(self, 500, {"error": str(e)})
            return

        sign_request_id = resp_data.get("sign_request_id", "")
        _store[sign_request_id] = {
            "exchange_code":  resp_data.get("exchange_code", ""),
            "status":         "pending",
            "signed_doc_url": None,
        }

        json_response(self, 200, {
            "sign_request_id": sign_request_id,
            "signing_url":     resp_data.get("signing_url", ""),
        })

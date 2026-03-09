"""
api/webhook/singpass.py — POST /api/webhook/singpass
Singpass calls this after a document is signed.
"""
import json, base64
from http.server import BaseHTTPRequestHandler
from api._shared import json_response, _store


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args): pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data  = json.loads(body)
            token = data.get("token", "")
            parts = token.split(".")
            if len(parts) == 3:
                padded  = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
                req_id     = payload.get("sign_request_id", "")
                signed_url = payload.get("signed_doc_url", "")
                if req_id and signed_url and req_id in _store:
                    _store[req_id].update({"status": "signed", "signed_doc_url": signed_url})
        except Exception:
            pass
        # Must respond 200 immediately — Singpass will retry if not
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

"""
api/status.py — GET /api/status?id=<sign_request_id>
Polls Singpass for signing result.
"""
import json, ssl, urllib.parse
import http.client
from http.server import BaseHTTPRequestHandler
from api._shared import (
    get_api_base, build_auth_token, json_response,
    get_env, SIGN_ENDPOINT, _store
)


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args): pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_GET(self):
        params     = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        req_id     = params.get("id", "")
        is_staging = params.get("staging", "1") == "1"

        record = _store.get(req_id)
        if not record:
            json_response(self, 404, {"error": "Session not found"})
            return

        if record["status"] == "signed":
            json_response(self, 200, {"status": "signed", "signed_doc_url": record["signed_doc_url"]})
            return

        client_id, private_key_pem, kid, _ = get_env()
        api_base   = get_api_base(is_staging)
        result_url = f"{api_base}{SIGN_ENDPOINT}/{req_id}/result"

        try:
            auth_token    = build_auth_token(client_id, private_key_pem, kid, result_url)
            exchange_code = record["exchange_code"]
            body_data     = json.dumps({"exchange_code": exchange_code}).encode()

            parsed = urllib.parse.urlparse(result_url)
            ctx    = ssl.create_default_context()
            conn   = http.client.HTTPSConnection(parsed.netloc, timeout=15, context=ctx)
            try:
                conn.request("POST", parsed.path, body=body_data, headers={
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type":  "application/json",
                    "Content-Length": str(len(body_data)),
                })
                resp   = conn.getresponse()
                result = json.loads(resp.read())
            finally:
                conn.close()

            signed_url = result.get("signed_doc_url") or result.get("download_url")
            if signed_url:
                _store[req_id].update({"status": "signed", "signed_doc_url": signed_url})
                json_response(self, 200, {"status": "signed", "signed_doc_url": signed_url})
            else:
                json_response(self, 200, {"status": "pending"})

        except (http.client.HTTPException, OSError):
            json_response(self, 200, {"status": "pending"})
        except Exception as e:
            json_response(self, 200, {"status": "pending", "debug": str(e)})
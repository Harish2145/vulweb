"""
Fake cloud-instance-metadata service, reachable only from the internal
docker network (never published to the host). Simulates AWS-style
169.254.169.254 metadata used to demonstrate SSRF -> credential theft.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_CREDS = """{
  "Code": "Success",
  "LastUpdated": "2026-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIALAB00000000FAKE",
  "SecretAccessKey": "LaBfAkEsEcReTkEyDoNoTuSe1234567890",
  "Token": "LAB-FAKE-SESSION-TOKEN",
  "Expiration": "2099-01-01T00:00:00Z"
}"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/latest/meta-data/iam/security-credentials/":
            self._send(200, "lab-role\n")
        elif self.path == "/latest/meta-data/iam/security-credentials/lab-role":
            self._send(200, FAKE_CREDS)
        elif self.path.startswith("/latest/meta-data"):
            self._send(200, "ami-id\nhostname\niam/\n")
        else:
            self._send(404, "not found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        print("[metadata] " + fmt % args)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()

"""
Exposes the prompt-injection-engine CLI as an HTTP endpoint so
LLM red-team tooling can probe it as if it were a model.

The "response" is the scanner verdict, not generated text:
  BLOCKED  -> a signature fired at or above threshold
  PASSED   -> nothing fired; the payload evaded detection

Any probe that comes back PASSED is a detection gap.
"""
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

import os
PIE = os.environ.get("PIE_BIN", "./target/debug/pie")

def scan(text: str) -> dict:
    proc = subprocess.run(
        [PIE, "scan", "-", "--format", "json"],
        input=text, capture_output=True, text=True,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"blocked": False, "clean": True, "detections": [], "error": proc.stderr[:200]}

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length) or b"{}")
        prompt = payload.get("prompt", "")

        result = scan(prompt)
        hits = result.get("detections", [])

        if hits:
            sigs = ",".join(h["signature_id"] for h in hits)
            verdict = f"BLOCKED severity={result.get('max_severity')} signatures={sigs}"
        else:
            verdict = "PASSED no detection"

        body = json.dumps({"text": verdict, "detections": hits}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # quiet

if __name__ == "__main__":
    print("scanner wrapper listening on http://127.0.0.1:8900/scan")
    HTTPServer(("127.0.0.1", 8900), Handler).serve_forever()

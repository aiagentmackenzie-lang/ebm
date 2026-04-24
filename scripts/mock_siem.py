#!/usr/bin/env python3
import http.server as hs
import json, sys

class MockSIEM(hs.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write(fmt % args + '\n')
        sys.stdout.flush()

    def do_GET(self):
        if self.path == '/api/v1/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}\n')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/v1/ingest':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            try:
                obj = json.loads(body)
                print(f'[MOCK] Received {len(obj)} events')
                for ev in obj:
                    cat = ev.get('event_category','?')
                    typ = ev.get('event_type','?')
                    sev = ev.get('severity','?')
                    print(f'[MOCK] event_category={cat} event_type={typ} severity={sev}')
                    # Print raw_data if present for alert detection
                    rd = ev.get('raw_data')
                    if rd:
                        print(f'[MOCK] raw_data={json.dumps(rd)[:500]}')
            except Exception as e:
                print(f'[MOCK] json parse error: {e}')
            self.send_response(202)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"accepted":len(obj),"message":f"Accepted {len(obj)} events"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    port = 8000
    srv = hs.HTTPServer(('127.0.0.1', port), MockSIEM)
    print(f'[MOCK] SIEM listening on port {port}')
    srv.serve_forever()

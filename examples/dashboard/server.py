#!/usr/bin/env python3
"""
Simple server for ZTE Dashboard example.
Serves static files and proxies API requests to the ZTE API server.
"""

import http.server
import json
import os
import urllib.request
import urllib.error

PORT = int(os.environ.get("PORT", "8080"))
ZTE_API_URL = os.environ.get("ZTE_API_URL", "http://localhost:8000")
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        # Proxy API requests to ZTE API server
        if self.path.startswith("/api/"):
            self.proxy_api()
        else:
            # Serve index.html for root
            if self.path == "/" or self.path == "":
                self.path = "/index.html"
            super().do_GET()

    def proxy_api(self):
        """Proxy requests to ZTE API server"""
        # Map /api/pon -> /pon, /api/lan -> /lan, etc.
        api_path = self.path.replace("/api", "", 1)

        try:
            req = urllib.request.Request(f"{ZTE_API_URL}{api_path}")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=15) as response:
                data = response.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)

        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def end_headers(self):
        # Add CORS headers
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()


def main():
    print(f"ZTE Dashboard Server")
    print(f"====================")
    print(f"Dashboard: http://localhost:{PORT}")
    print(f"ZTE API:   {ZTE_API_URL}")
    print()

    with http.server.HTTPServer(("", PORT), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")


if __name__ == "__main__":
    main()

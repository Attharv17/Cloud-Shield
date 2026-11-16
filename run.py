"""
CloudShield - Simple Local Server Launcher
College Project: Adaptive Cloud Threat Detection & Explainable Risk Scoring

Usage:
    python run.py

This starts a lightweight HTTP server on port 8000 and automatically
opens the CloudShield dashboard in your default browser.
No external Python dependencies or database setup required.
"""

import http.server
import socketserver
import os
import sys
import webbrowser
import threading
import time

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class CloudShieldHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        # Format clean, minimal server request logs
        sys.stdout.write(f"[CloudShield Log] {self.address_string()} - {format % args}\n")

def open_browser():
    time.sleep(0.8)
    url = f"http://127.0.0.1:{PORT}/index.html"
    print(f"\nOpening browser at: {url}\n")
    webbrowser.open(url)

def main():
    os.chdir(DIRECTORY)
    
    # Allow socket address reuse so restarting immediately doesn't throw 'Address in use'
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        with socketserver.TCPServer(("127.0.0.1", PORT), CloudShieldHTTPHandler) as httpd:
            print("=" * 70)
            print("  CloudShield - Adaptive Cloud Threat Detection & Risk Scoring")
            print("  College Project Viva & Demonstration Server")
            print("=" * 70)
            print(f"  Server URL: http://127.0.0.1:{PORT}/")
            print(f"  Root Dir:   {DIRECTORY}")
            print("  Status:     Online & Monitoring Active")
            print("=" * 70)
            print("  Press Ctrl+C to stop the server.\n")

            threading.Thread(target=open_browser, daemon=True).start()
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[CloudShield] Server stopped safely.")
        sys.exit(0)
    except OSError as e:
        print(f"\n[Error] Could not bind to port {PORT}: {e}")
        print(f"Try running on another port or check if another process is using port {PORT}.")
        sys.exit(1)

if __name__ == "__main__":
    main()


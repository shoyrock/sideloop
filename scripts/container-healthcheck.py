import os
import socket
import urllib.request


def main():
    port = int(os.environ.get("UI_PORT", "8080"))
    anisette = os.environ.get("ANISETTE_SERVER", "http://127.0.0.1:6969")
    for url in (f"http://127.0.0.1:{port}/api/health", anisette):
        with urllib.request.urlopen(url, timeout=4) as response:
            response.read(64)
    if os.environ.get("MUX", "builtin") == "builtin":
        with socket.create_connection(("127.0.0.1", 27015), timeout=4):
            pass


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import socket
import sys
import json
from urllib.parse import urlparse, parse_qs

import time

INTERVAL = 30  # seconds until next announce
TIMEOUT = 120  # seconds without announce before a peer is considered dead

torrents = {}

def cleanup_peers():
    """Remove peers that have not announced recently and log active torrents."""
    now = time.time()
    to_delete = []

    for info_hash, peers in torrents.items():
        # Filter out stale peers
        alive = []
        for p in peers:
            last = p.get("last_announce", 0)
            if now - last <= TIMEOUT:
                alive.append(p)
        if alive:
            torrents[info_hash] = alive
        else:
            to_delete.append(info_hash)

    for ih in to_delete:
        del torrents[ih]

    # Log active torrents and participating peers
    if torrents:
        print("[TRACKER] Active torrents:")
        for info_hash, peers in torrents.items():
            print(f"  info_hash={info_hash} peers={len(peers)}")
    else:
        print("[TRACKER] No active torrents")

def handle_announce(path, peer_ip):
    """Handle URL /announce?info_hash=...&peer_id=...&peer_port=...&status=..."""

    parsedUrl = urlparse(path)
    urlQuery = parse_qs(parsedUrl.query)

    info_hash = urlQuery.get("info_hash", [None])[0]
    peer_id = urlQuery.get("peer_id", [None])[0]
    peer_port = urlQuery.get("peer_port", [None])[0]
    status = urlQuery.get("status", ["started"])[0]

    if not info_hash or not peer_id or not peer_port:
        return 400, {"error": "Missing required parameters"}
    
    try:
        peer_port = int(peer_port)
    except ValueError:
        return 400, {"error": "Invalid peer_port"}
    
    # Get or create the list of peers for the info_hash
    peers = torrents.setdefault(info_hash, [])

    now = time.time()
    existing_peer = None
    for peer in peers:
        if peer["peer_id"] == peer_id:
            existing_peer = peer
            break

    if existing_peer:
        # Update existing peer info
        existing_peer["ip"] = peer_ip
        existing_peer["port"] = peer_port
        existing_peer["status"] = status
        existing_peer["last_announce"] = now
    else:
        # Add new peer
        peers.append(
            {
                "peer_id": peer_id,
                "ip": peer_ip,
                "port": peer_port,
                "status": status,
                "last_announce": now,
            }
        )

    # Build a response
    response_peers = [
        {"peer_id": p["peer_id"], "ip": p["ip"], "port": p["port"]}
        for p in peers
    ]

    return 200, {"interval": INTERVAL, "peers": response_peers}

def read_http_request(socket):
    """Read an HTTP request from a TCP socket and return the request method and path/URL."""

    data = b""

    while b"\r\n\r\n" not in data:  # Double CRLF indicates end of headers in an HTTP request message
        chunk = socket.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 8192:  # Limit to 8 KB
            break

    if not data:
        return None, None

    # Decode the HTTP request
    try:
        request_text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, None

    # Parse the HTTP request line
    request_lines = request_text.split("\r\n")  # First CRLF separates request line from headers
    if not request_lines:
        return None, None

    request_line = request_lines[0]
    parts = request_line.split()
    if len(parts) < 2:
        return None, None

    method = parts[0]
    path = parts[1]

    return method, path

def send_http_response(socket, status_code, body_dict):
    """Send an HTTP response with the given status code and JSON body."""

    reasons = {200: "OK", 400: "Bad Request", 404: "Not Found"}
    reason = reasons.get(status_code, "Unknown")

    body_json = json.dumps(body_dict)
    response_lines = [
        f"HTTP/1.1 {status_code} {reason}",
        "Content-Type: application/json",
        f"Content-Length: {len(body_json)}",
        "Connection: close",  # Tracker server will close connection
        "",
        body_json
    ]
    response_text = "\r\n".join(response_lines)

    socket.sendall(response_text.encode("utf-8"))

def run_tracker(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind(("0.0.0.0", port))
        s.listen(50)
        
        print(f"RUNNING: Tracker listening on 0.0.0.0:{port}!")

        while True:
            conn, addr = s.accept()
            client_ip, _ = addr
            with conn:
                method, path = read_http_request(conn)
                if method != "GET" or path is None:
                    send_http_response(conn, 400, {"error": "bad request"})
                    continue

                parsed = urlparse(path)
                if parsed.path != "/announce":
                    send_http_response(conn, 404, {"error": "not found"})
                    continue

                status, body = handle_announce(path, client_ip)
                send_http_response(conn, status, body)
                cleanup_peers()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>")
        sys.exit(1)
    port = int(sys.argv[1])
    run_tracker(port)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import socket
import sys
import json
from urllib.parse import urlparse, parse_qs

INTERVAL = 30  # seconds until next announce

torrents = {}

def handle_announce(path, peer_ip):
    """Handle URL /announce?info_hash=...&peer_id=...&peer_port=..."""

    parsedUrl = urlparse(path)
    urlQuery = parse_qs(parsedUrl.query)

    info_hash = urlQuery.get("info_hash", [None])[0]
    peer_id = urlQuery.get("peer_id", [None])[0]
    peer_port = urlQuery.get("peer_port", [None])[0]

    if not info_hash or not peer_id or not peer_port:
        return 400, {"error": "Missing required parameters"}
    
    try:
        peer_port = int(peer_port)
    except ValueError:
        return 400, {"error": "Invalid peer_port"}
    
    # Get or create the list of peers for the info_hash
    peers = torrents.setdefault(info_hash, [])

    # Check if peer already exists in dictionary
    existing_peer = None
    for peer in peers:
        if peer["peer_id"] == peer_id:
            existing_peer = peer
            break

    if existing_peer:
        # Update existing peer info
        existing_peer["ip"] = peer_ip
        existing_peer["port"] = peer_port
    else:
        # Add new peer
        peers.append({"peer_id": peer_id, "ip": peer_ip, "port": peer_port})

    return 200, {"interval": INTERVAL, "peers": peers}

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
        "Connection: close",  # Server will close connection
        "",
        body_json
    ]
    response_text = "\r\n".join(response_lines)
    
    socket.sendall(response_text.encode("utf-8"))
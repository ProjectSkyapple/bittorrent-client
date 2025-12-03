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
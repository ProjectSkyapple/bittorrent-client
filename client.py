#!/usr/bin/env python3
import sys
import time
import random
import json
import urllib.parse

import requests

from torrent_metadata import TorrentMetadata
from file_manager import FileManager
from peer import PieceManager, PeerServer, connect_to_peer

LISTEN_IP = "0.0.0.1"
LISTEN_PORT = 6881  # fixed for simplicity


def random_peer_id():
    prefix = "-UTDBT0-"
    suffix_len = 20 - len(prefix)
    suffix = "".join(random.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(suffix_len))
    return prefix + suffix


def announce_to_tracker(metadata, peer_id, port):
    """Make an announce request to the project tracker and return a list of (ip, port) peers."""
    info_hash_bytes = metadata.info_hash_bytes
    announce_url = metadata.announce

    # Build query parameters. info_hash and peer_id are treated as raw bytes and
    # URL-encoded explicitly to match what the tracker expects.
    params = {
        "info_hash": info_hash_bytes,
        "peer_id": peer_id.encode("utf-8"),
        "peer_port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": metadata.length,
        "status": "started",
    }

    encoded_params = []
    for k, v in params.items():
        if isinstance(v, bytes):
            encoded = urllib.parse.quote_from_bytes(v)
        else:
            encoded = urllib.parse.quote(str(v))
        encoded_params.append(f"{k}={encoded}")
    query = "&".join(encoded_params)
    url = f"{announce_url}?{query}"

    print("[CLIENT] GET to tracker", url)

    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to contact tracker: {e}") from e

    try:
        decoded = json.loads(resp.text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Tracker returned invalid JSON: {e}") from e

    # Expect a JSON dict with "peers": [{"ip": ..., "port": ...}, ...]
    if "error" in decoded:
        raise RuntimeError(f"Tracker failure: {decoded['error']}")

    peers_list = decoded.get("peers", [])
    peers = []
    for p in peers_list:
        try:
            ip = p["ip"]
            port_num = int(p["port"])
            peers.append((ip, port_num))
        except (KeyError, ValueError, TypeError):
            continue

    return peers


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} FILE.torrent OUTPUT_FILE")
        sys.exit(1)

    torrent_path = sys.argv[1]
    output_path = sys.argv[2]

    # Load metadata
    meta = TorrentMetadata(torrent_path)
    print("[CLIENT] Loaded torrent:", meta)

    num_pieces = meta.num_pieces

    # Piece & file managers
    piece_manager = PieceManager(num_pieces)
    file_manager = FileManager(output_path, meta)

    # Generate peer_id
    peer_id = random_peer_id()
    print("[CLIENT] Our peer_id:", peer_id)

    # Start peer server for incoming peers
    server = PeerServer(
        ip=LISTEN_IP,
        port=LISTEN_PORT,
        metadata=meta,
        peer_id=peer_id,
        piece_manager=piece_manager,
        file_manager=file_manager,
    )
    server.start()

    # Ask tracker for peers
    try:
        peers = announce_to_tracker(meta, peer_id, LISTEN_PORT)
    except Exception as e:
        print("[CLIENT] Tracker error:", e)
        peers = []

    # Filter out ourselves (if tracker gave us back our own address)
    peers = list({(ip, port) for ip, port in peers})
    peers = [(ip, port) for ip, port in peers if not (ip == LISTEN_IP and port == LISTEN_PORT)]
    print(f"[CLIENT] Tracker returned {len(peers)} peers:", peers)

    connections = []
    for ip, port in peers:
        try:
            conn = connect_to_peer(
                ip,
                port,
                meta,
                peer_id,
                piece_manager,
                file_manager=file_manager,
            )
            connections.append(conn)
        except Exception as e:
            print(f"[CLIENT] Failed to connect to {ip}:{port} -> {e}")

    if not connections:
        print("[CLIENT] No outgoing connections established. Waiting for incoming peers only...")
        time.sleep(1.0)

    print("\n[ENGINE] Starting multi-peer download loop...\n")

    max_rounds = 1000
    round_delay = 0.2

    for round_no in range(max_rounds):
        if all(piece_manager.have):
            print(f"[ENGINE] All pieces downloaded in {round_no} rounds!")
            break

        made_request = False

        for conn in connections[:]:
            if conn.remote_have is None:
                continue

            piece_to_request = None
            for index in range(num_pieces):
                if not piece_manager.have[index] and conn.remote_have[index]:
                    piece_to_request = index
                    break

            if piece_to_request is not None:
                print(f"[ENGINE] Requesting piece {piece_to_request} from {conn.remote_peer_id or conn.client_addr}")
                try:
                    conn.request_piece(piece_to_request)
                    made_request = True
                except Exception as e:
                    print(f"[ENGINE] Failed to request piece {piece_to_request} from {conn.client_addr}: {e}")

        time.sleep(round_delay)

    else:
        print("[ENGINE] Download loop hit max_rounds without completing.")

    print("\n[ENGINE] Final have[] =", piece_manager.have)
    have_count = sum(1 for h in piece_manager.have if h)
    print(f"[ENGINE] Pieces complete: {have_count}/{num_pieces}")

    print("[CLIENT] Stopping server...")
    server.stop()
    time.sleep(0.5)


if __name__ == "__main__":
    main()
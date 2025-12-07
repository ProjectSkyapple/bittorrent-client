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

LISTEN_PORT = None  # no longer used; per-client port is now CLI-driven


def random_peer_id():
    prefix = "-UTDBT0-"
    suffix_len = 20 - len(prefix)
    suffix = "".join(random.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(suffix_len))
    return prefix + suffix


def announce_to_tracker(metadata, peer_id, port, status = "started"):
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
        "status": status,
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

    interval = int(decoded.get("interval", 30))
    return peers, interval


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} LISTEN_PORT FILE.torrent OUTPUT_FILE")
        sys.exit(1)

    listen_port = int(sys.argv[1])
    torrent_path = sys.argv[2]
    output_path = sys.argv[3]

    # All clients run on localhost; only the port differentiates them.
    listen_ip = "127.0.0.1"

    # Load metadata
    meta = TorrentMetadata(torrent_path)
    print("[CLIENT] Loaded torrent:", meta)

    num_pieces = meta.num_pieces

    # Piece & file managers
    piece_manager = PieceManager(num_pieces)
    file_manager = FileManager(output_path, meta)

    # Bootstrap PieceManager from what FileManager found on disk. If the
    # output file is already complete and matches the torrent (seeder),
    # FileManager.scan_existing_pieces() will have marked its internal
    # have[] array accordingly, and we mirror that into PieceManager so
    # our bitfield and all_complete() reflect the correct initial state.
    for i in range(num_pieces):
        if file_manager.has_piece(i):
            piece_manager.mark_have(i)

    # Generate peer_id
    peer_id = random_peer_id()
    print("[CLIENT] Our peer_id:", peer_id)

    # Start peer server for incoming peers
    server = PeerServer(
        ip=listen_ip,
        port=listen_port,
        metadata=meta,
        peer_id=peer_id,
        piece_manager=piece_manager,
        file_manager=file_manager,
    )
    server.start()

    # Ask tracker for peers
    try:
        peers, interval = announce_to_tracker(meta, peer_id, listen_port)
    except Exception as e:
        print("[CLIENT] Tracker error:", e)
        peers = []
        interval = 30

    # Filter out ourselves (if tracker gave us back our own address)
    peers = list({(ip, port) for ip, port in peers})
    peers = [(ip, port) for ip, port in peers if not (ip == listen_ip and port == listen_port)]
    print(f"[CLIENT] Tracker returned {len(peers)} peers:", peers)

    next_announce_at = time.time() + interval

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
    completed = False

    for round_no in range(max_rounds):
        now = time.time()
        if now >= next_announce_at:
            try:
                new_peers, interval = announce_to_tracker(meta, peer_id, listen_port)
                next_announce_at = now + interval

                # Merge in any newly discovered peers (avoid duplicates and ourselves)
                new_peers = list({(ip, port) for ip, port in new_peers})
                new_peers = [
                    (ip, port)
                    for ip, port in new_peers
                    if not (ip == listen_ip and port == listen_port)
                ]

                existing_addrs = {(c.client_addr[0], c.client_addr[1]) for c in connections}
                for ip, port in new_peers:
                    if (ip, port) in existing_addrs:
                        continue
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
                        existing_addrs.add((ip, port))
                        print(f"[CLIENT] Connected to new peer from tracker: {(ip, port)}")
                    except Exception as e:
                        print(f"[CLIENT] Failed to connect to {ip}:{port} from periodic announce -> {e}")

            except Exception as e:
                print("[CLIENT] Periodic tracker announce failed:", e)

        if piece_manager.all_complete():
            print(f"[ENGINE] All pieces downloaded in {round_no} rounds!")
            completed = True
            break

        made_request = False
        dead_connections = []

        # Take a thread-safe snapshot of our local have[] state for this round.
        local_have = piece_manager.snapshot_have()

        for conn in connections[:]:
            # If the underlying PeerConnection thread is no longer alive, drop it.
            if not conn.is_alive():
                dead_connections.append(conn)
                continue

            if conn.remote_have is None:
                continue

            piece_to_request = None
            for index in range(num_pieces):
                if not local_have[index] and conn.remote_have[index]:
                    piece_to_request = index
                    break

            if piece_to_request is not None:
                print(f"[ENGINE] Requesting piece {piece_to_request} from {conn.remote_peer_id or conn.client_addr}")
                try:
                    conn.request_piece(piece_to_request)
                    made_request = True
                except Exception as e:
                    print(f"[ENGINE] Failed to request piece {piece_to_request} from {conn.client_addr}: {e}")
                    dead_connections.append(conn)

        # Remove any dead/broken connections from our active list.
        for dc in dead_connections:
            if dc in connections:
                connections.remove(dc)
                print(f"[ENGINE] Dropped dead connection to {dc.client_addr}")

        time.sleep(round_delay)

    else:
        print("[ENGINE] Download loop hit max_rounds without completing.")

    final_have = piece_manager.snapshot_have()
    print("\n[ENGINE] Final have[] =", final_have)
    have_count = sum(1 for h in final_have if h)
    print(f"[ENGINE] Pieces complete: {have_count}/{num_pieces}")

    # If we completed the download, stay up as a seeder so other peers can fetch pieces.
    if completed and all(final_have):
        print("\n[SEED] Download complete. Staying online to seed.")
        print("[SEED] Press Ctrl+C to stop seeding and shut down the client.\n")
        try:
            while True:
                try:
                    # Announce to the tracker as a completed peer so new leechers can discover us.
                    announce_to_tracker(meta, peer_id, listen_port, status="completed")
                except Exception as e:
                    print(f"[SEED] Tracker announce failed: {e}")
                # Sleep for a while before the next announce. This does not block peer threads.
                time.sleep(30.0)
        except KeyboardInterrupt:
            print("\n[SEED] Stopping seeding on user request...")

    # Tell the tracker we are leaving the swarm.
    try:
        announce_to_tracker(meta, peer_id, listen_port, status="stopped")
    except Exception as e:
        print(f"[CLIENT] Failed to send stopped announce: {e}")

    print("[CLIENT] Stopping server...")
    server.stop()
    time.sleep(0.5)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import time

from torrent_metadata import TorrentMetadata
from file_manager import FileManager
from peer import (
    PieceManager,
    PeerServer,
    connect_to_peer,
)

# Paths for the demo. Adjust these to point to a real .torrent and its corresponding file.
TORRENT_PATH = "./test_leecher_files/alice.torrent"          # TODO: set this to a real .torrent file
SEEDER_FILE_PATH = "./test_seeder_files/alice.txt"  # The complete file that matches the torrent (for seeding)
LEECHER_FILE_PATH = "./test_leecher_files/alice_download"  # Where the leecher will download to


def main():
    # Load real torrent metadata
    metadata = TorrentMetadata(TORRENT_PATH)
    print("[DEMO] Loaded torrent:", metadata)

    num_pieces = metadata.num_pieces

    # --- Seeder setup ---
    seeder_pm = PieceManager(num_pieces)
    seeder_fm = FileManager(SEEDER_FILE_PATH, metadata)

    # Seeder: verify existing file and mark pieces as available.
    # This assumes SEEDER_FILE_PATH already contains the complete file
    # that matches the .torrent.
    for i in range(num_pieces):
        data = seeder_fm.read_piece(i)
        if data is None:
            continue
        # Re-verify and mark have; write_piece will check SHA1 and update seeder_fm.have
        if seeder_fm.write_piece(i, data):
            seeder_pm.mark_have(i)

    seeder_peer_id = "seeder-peer"

    seeder_server = PeerServer(
        ip="127.0.0.1",
        port=9001,
        metadata=metadata,
        peer_id=seeder_peer_id,
        piece_manager=seeder_pm,
        file_manager=seeder_fm,
    )
    seeder_server.start()

    # Give the server time to start listening
    time.sleep(0.2)

    # --- Leecher setup ---
    leecher_pm = PieceManager(num_pieces)
    leecher_fm = FileManager(LEECHER_FILE_PATH, metadata)
    leecher_peer_id = "leecher-peer"

    # Outgoing connection from leecher -> seeder
    conn = connect_to_peer(
        "127.0.0.1",
        9001,
        metadata,
        leecher_peer_id,
        leecher_pm,
        file_manager=leecher_fm,
    )

    # Wait a bit for handshake + bitfield exchange
    time.sleep(0.5)

    print("\n[ENGINE] Starting simple download loop...\n")

    # We'll repeatedly scan for missing pieces and request them
    # until we have all pieces or a timeout.
    max_rounds = 200
    round_delay = 0.1

    for round_no in range(max_rounds):
        # If we already have all pieces, we're done.
        if all(leecher_pm.have):
            print(f"[ENGINE] All pieces downloaded in {round_no} rounds!")
            break

        # If we don't yet know what the remote has, wait.
        if conn.remote_have is None:
            print("[ENGINE] Waiting for remote bitfield...")
            time.sleep(round_delay)
            continue

        # Pick one missing piece that the remote has.
        piece_to_request = None
        for index in range(num_pieces):
            if not leecher_pm.have[index] and conn.remote_have[index]:
                piece_to_request = index
                break

        if piece_to_request is None:
            # Remote doesn't have anything we need (or remote_have is out of sync).
            print("[ENGINE] No requestable pieces found this round.")
            time.sleep(round_delay)
            continue

        print(f"[ENGINE] Requesting piece {piece_to_request}")
        conn.request_piece(piece_to_request)

        # Give the peer connection time to process REQUEST/PIECE
        time.sleep(round_delay)

    else:
        print("[ENGINE] Download loop hit max_rounds without completing.")

    print("\n[ENGINE] Final leecher have[] =", leecher_pm.have)
    for i in range(num_pieces):
        data = leecher_fm.read_piece(i)
        print(f"[ENGINE] piece {i}: {data!r}")

    # Clean up
    seeder_server.stop()
    time.sleep(0.2)


if __name__ == "__main__":
    main()
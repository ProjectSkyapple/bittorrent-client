#!/usr/bin/env python3
import time

from peer import (
    TorrentMetadata,
    PieceManager,
    FileManager,
    PeerServer,
    connect_to_peer,
)


NUM_PIECES = 8
PIECE_SIZE = 16  # bytes, arbitrary for demo


def make_dummy_piece_data(index):
    # Just some deterministic content per piece so we can recognize it
    return f"piece-{index:02d}".encode("utf-8").ljust(PIECE_SIZE, b"_")


def main():
    metadata = TorrentMetadata()

    seeder_pm = PieceManager(NUM_PIECES)
    seeder_fm = FileManager(NUM_PIECES, PIECE_SIZE)

    # Seeder has ALL pieces
    for i in range(NUM_PIECES):
        data = make_dummy_piece_data(i)
        ok = seeder_fm.write_piece(i, data)
        if ok:
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

    leecher_pm = PieceManager(NUM_PIECES)
    leecher_fm = FileManager(NUM_PIECES, PIECE_SIZE)
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
    max_rounds = 50
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
        for index in range(NUM_PIECES):
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
    for i in range(NUM_PIECES):
        data = leecher_fm.read_piece(i)
        print(f"[ENGINE] piece {i}: {data!r}")

    # Clean up
    seeder_server.stop()
    time.sleep(0.2)


if __name__ == "__main__":
    main()
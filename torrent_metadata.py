# torrent_metadata.py
import hashlib
import bencodepy


class TorrentMetadata:
    def __init__(self, torrent_path):
        # Load and parse .torrent file using bencodepy
        with open(torrent_path, "rb") as f:
            raw = f.read()

        meta = bencodepy.decode(raw)

        # Most keys are bytes
        info = meta[b"info"]
        # announce = meta[b"announce"]

        # Compute info_hash (MUST be bencoded EXACTLY as stored)
        info_bencoded = bencodepy.encode(info)
        self.info_hash_bytes = hashlib.sha1(info_bencoded).digest()
        self.info_hash_hex = self.info_hash_bytes.hex()

        # Tracker URL
        self.announce = "http://127.0.0.1:6969/announce" # tracker.py (port MUST be 6969)

        # Single-file torrent fields
        self.name = info[b"name"].decode("utf-8")
        self.length = info[b"length"]
        self.piece_length = info[b"piece length"]

        # Extract piece hashes (20 bytes each)
        pieces_blob = info[b"pieces"]
        if len(pieces_blob) % 20 != 0:
            raise ValueError("Invalid 'pieces' field (not divisible by 20).")

        self.piece_hashes = [
            pieces_blob[i:i+20] for i in range(0, len(pieces_blob), 20)
        ]
        self.num_pieces = len(self.piece_hashes)

    def __repr__(self):
        return (
            f"TorrentMetadata(name={self.name!r}, length={self.length}, "
            f"piece_length={self.piece_length}, num_pieces={self.num_pieces})"
        )
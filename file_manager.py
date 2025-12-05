# file_manager.py
import os
import hashlib


class FileManager:
    """
    File manager for a single-file torrent.
    """

    def __init__(self, download_path, metadata):
        """
        :param download_path: Path to the file we are downloading (or seeding).
        :param metadata: Parsed TorrentMetadata for this torrent.
        """
        self.download_path = download_path
        self.meta = metadata

        self.num_pieces = metadata.num_pieces
        self.piece_length = metadata.piece_length
        self.total_length = metadata.length
        self.piece_hashes = metadata.piece_hashes

        # Track which pieces we have verified on disk
        self.have = [False] * self.num_pieces

        # Ensure file exists and has correct size (sparse file is fine)
        self._ensure_file()


    def _ensure_file(self):
        """
        Ensure that the download file exists and is at least total_length bytes.
        Creates a sparse file if needed.
        """
        flags = os.O_RDWR | os.O_CREAT
        # 0o666 => rw-rw-rw- (umask may restrict this further)
        fd = os.open(self.download_path, flags, 0o666)
        try:
            current_size = os.lseek(fd, 0, os.SEEK_END)
            if current_size < self.total_length:
                # Extend file to total_length bytes
                os.lseek(fd, self.total_length - 1, os.SEEK_SET)
                os.write(fd, b"\0")
        finally:
            os.close(fd)

    def _piece_bounds(self, index):
        """
        Return (start_offset, length) in bytes for the given piece index.
        The last piece may be shorter than piece_length.
        """
        if not (0 <= index < self.num_pieces):
            raise IndexError(f"Piece index {index} out of range 0..{self.num_pieces-1}")

        start = index * self.piece_length
        if index == self.num_pieces - 1:
            length = self.total_length - start
        else:
            length = self.piece_length
        return start, length

    def has_piece(self, index):
        """
        Return True if we have successfully verified and stored this piece on disk.
        """
        return 0 <= index < self.num_pieces and self.have[index]

    def read_piece(self, index):
        """
        Read a piece from disk.
        """
        if not (0 <= index < self.num_pieces):
            return None

        start, length = self._piece_bounds(index)
        with open(self.download_path, "rb") as f:
            f.seek(start)
            data = f.read(length)

        if len(data) != length:
            # File truncated or corrupted
            return None
        return data

    def write_piece(self, index, data):
        """
        Verify and write a piece to disk.
        """
        if not (0 <= index < self.num_pieces):
            print(f"[FileManager] Rejecting piece {index}: out of range")
            return False

        start, length = self._piece_bounds(index)
        if len(data) != length:
            print(
                f"[FileManager] Piece {index} wrong length: "
                f"got {len(data)}, expected {length}"
            )
            return False

        expected_hash = self.piece_hashes[index]
        actual_hash = hashlib.sha1(data).digest()
        if actual_hash != expected_hash:
            print(f"[FileManager] Piece {index} failed SHA1 verification")
            return False

        # Write verified data to disk
        with open(self.download_path, "r+b") as f:
            f.seek(start)
            f.write(data)

        self.have[index] = True
        return True
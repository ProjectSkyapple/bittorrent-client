# file_manager.py
import os
import hashlib
import threading


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

        # Lock to synchronize access to have[] and the underlying file
        # across multiple PeerConnection threads.
        self._lock = threading.Lock()

        # Ensure file exists and has correct size (sparse file is fine)
        self._ensure_file()

        # If the file already contains valid data (e.g., we're a seeder or
        # partial seeder), scan it and mark which pieces we already have.
        self.scan_existing_pieces()


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

    def scan_existing_pieces(self):
        """
        Scan the existing file on disk and mark which pieces we already have
        (i.e., pieces that pass the SHA1 check). This is called at
        initialization time before any peer threads are started.
        """
        found = 0
        for index in range(self.num_pieces):
            data = self.read_piece(index)
            if data is None:
                continue

            expected_hash = self.piece_hashes[index]
            actual_hash = hashlib.sha1(data).digest()
            if actual_hash == expected_hash:
                # Mark this piece as present. We take the lock because read_piece
                # also uses the same lock, but scan_existing_pieces runs before
                # any other threads are started.
                with self._lock:
                    self.have[index] = True
                found += 1

        if found:
            print(f"[FileManager] Verified {found}/{self.num_pieces} pieces from existing file")

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
        with self._lock:
            return 0 <= index < self.num_pieces and self.have[index]

    def read_piece(self, index):
        """
        Read a piece from disk.
        """
        if not (0 <= index < self.num_pieces):
            return None

        with self._lock:
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

        # We take the lock around bounds calculation, verification, and write
        # so that multiple PeerConnection threads cannot race on the file or
        # the have[] array.
        with self._lock:
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
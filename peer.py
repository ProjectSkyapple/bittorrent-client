#!/usr/bin/env python3
import socket
import threading
import struct

# Custom, BitTorrent-like message types ------
MESSAGE_HANDSHAKE = 1
MESSAGE_BITFIELD = 2
MESSAGE_REQUEST = 3
MESSAGE_PIECE = 4
MESSAGE_HAVE = 5
MESSAGE_KEEPALIVE = 6

class TorrentMetadata:
    def __init__(self):
        self.info_hash = "my-dummy-info-hash"  # TODO: Replace with actual info hash

class PieceManager:
    """Track which pieces a peer has and generate a bitfield."""

    def __init__(self, num_pieces: int):
        self.num_pieces = num_pieces
        # True if we have the piece at that index
        self.have = [False] * num_pieces  # Start off as a leecher

    def mark_have(self, index: int) -> None:
        if 0 <= index < self.num_pieces:
            self.have[index] = True

    def bitfield_bytes(self) -> bytes:
        """Return a compact bitfield: 1 bit per piece (MSB-first)."""
        bits = []
        for have_piece in self.have:
            bits.append('1' if have_piece else '0')
        # Pad to a multiple of 8 bits
        while len(bits) % 8 != 0:
            bits.append('0')
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte_bits = ''.join(bits[i:i+8])
            result.append(int(byte_bits, 2))
        return bytes(result)

    @staticmethod
    def parse_bitfield(b: bytes, num_pieces: int) -> list[bool]:
        """Parse a bitfield bytes object into a list of booleans of length num_pieces."""
        if not b or num_pieces <= 0:
            return [False] * max(num_pieces, 0)
        # Convert bytes -> bit string
        bits = bin(int.from_bytes(b, byteorder="big"))[2:]
        # Left-pad with zeros so we have 8 * len(b) bits
        bits = bits.zfill(len(b) * 8)
        # Take only the first num_pieces bits
        result = []
        for i in range(num_pieces):
            result.append(bits[i] == '1')
        return result

class FileManager:
    def __init__(self, num_pieces: int, piece_size: int):
        self.num_pieces = num_pieces
        self.piece_size = piece_size
        # None means we don't have the piece yet
        self._pieces: list[bytes | None] = [None] * num_pieces

    def has_piece(self, index: int) -> bool:
        return 0 <= index < self.num_pieces and self._pieces[index] is not None

    def read_piece(self, index: int) -> bytes | None:
        if 0 <= index < self.num_pieces:
            return self._pieces[index]
        return None

    def write_piece(self, index: int, data: bytes) -> bool:
        if 0 <= index < self.num_pieces:
            self._pieces[index] = data
            return True
        return False

class PeerConnection(threading.Thread):
    def __init__(self, client_conn, client_addr, server_metadata, server_peer_id, piece_manager, is_incoming: bool = True, file_manager: FileManager | None = None):
        super().__init__(daemon=True)

        self.client_conn = client_conn
        self.client_addr = client_addr  # (ip, port)
        self.server_metadata = server_metadata
        self.server_peer_id = server_peer_id
        self.piece_manager = piece_manager
        self.is_incoming = is_incoming
        self.file_manager = file_manager

        self.remote_peer_id = None  # Remote peer ID
        self.remote_have: list[bool] | None = None

    def run(self):
        print(f"[Peer {self.server_peer_id}] [Peer connection] Started for remote peer {self.client_addr}")

        try:
            # Handshake phase ------
            if self.is_incoming:
                # Incoming connection: remote peer initiates the handshake.
                message_type, payload = receive_message(self.client_conn)
                if message_type != MESSAGE_HANDSHAKE or payload is None or len(payload) < 40:
                    # 20 bytes info_hash + 20 bytes peer_id, TODO change if needed
                    print(
                        f"[Peer {self.server_peer_id}] [Peer connection] Invalid incoming handshake from {self.client_addr}"
                    )
                    return

                info_hash_bytes = payload[:20]
                remote_peer_id_bytes = payload[20:40]

                remote_info_hash = info_hash_bytes.decode("utf-8", errors="ignore").rstrip("_")
                self.remote_peer_id = remote_peer_id_bytes.decode("utf-8", errors="ignore").rstrip("_")

                print(
                    f"[Peer {self.server_peer_id}] [Peer connection] Got incoming handshake from {self.remote_peer_id}, "
                    f"info hash: {remote_info_hash}"
                )

                if remote_info_hash != self.server_metadata.info_hash:
                    print(f"[Peer {self.server_peer_id}] [Peer connection] Info hash mismatch, closing...")
                    return

                # Send our handshake response back to the remote peer
                my_info_hash_bytes = self.server_metadata.info_hash.encode("utf-8")[:20].ljust(20, b"_")  # TODO: real BitTorrent-style handshake
                my_peer_id_bytes = self.server_peer_id.encode("utf-8")[:20].ljust(20, b"_")
                handshake_payload = my_info_hash_bytes + my_peer_id_bytes
                send_message(self.client_conn, MESSAGE_HANDSHAKE, handshake_payload)

                print(f"[Peer {self.server_peer_id}] [Peer connection] Handshake (incoming) complete with {self.remote_peer_id}")

            else:
                # Outgoing connection: we initiate the handshake.
                my_info_hash_bytes = self.server_metadata.info_hash.encode("utf-8")[:20].ljust(20, b"_")
                my_peer_id_bytes = self.server_peer_id.encode("utf-8")[:20].ljust(20, b"_")
                handshake_payload = my_info_hash_bytes + my_peer_id_bytes
                send_message(self.client_conn, MESSAGE_HANDSHAKE, handshake_payload)
                print(
                    f"[Peer {self.server_peer_id}] [Peer connection] Sent outgoing handshake to {self.client_addr}"
                )

                message_type, payload = receive_message(self.client_conn)
                if message_type != MESSAGE_HANDSHAKE or payload is None or len(payload) < 40:
                    print(
                        f"[Peer {self.server_peer_id}] [Peer connection] Invalid handshake response from {self.client_addr}"
                    )
                    return

                info_hash_bytes = payload[:20]
                remote_peer_id_bytes = payload[20:40]

                remote_info_hash = info_hash_bytes.decode("utf-8", errors="ignore").rstrip("_")
                self.remote_peer_id = remote_peer_id_bytes.decode("utf-8", errors="ignore").rstrip("_")

                print(
                    f"[Peer {self.server_peer_id}] [Peer connection] Got handshake response from {self.remote_peer_id}, "
                    f"info hash: {remote_info_hash}"
                )

                if remote_info_hash != self.server_metadata.info_hash:
                    print(f"[Peer {self.server_peer_id}] [Peer connection] Info hash mismatch (outgoing), closing...")
                    return

                print(f"[Peer {self.server_peer_id}] [Peer connection] Handshake (outgoing) complete with {self.remote_peer_id}")

            # After a successful handshake (incoming or outgoing), send our bitfield.
            local_bitfield = self.piece_manager.bitfield_bytes()
            if local_bitfield:
                send_message(self.client_conn, MESSAGE_BITFIELD, local_bitfield)
                print(
                    f"[Peer {self.server_peer_id}] [Peer connection] Sent bitfield to remote peer {self.remote_peer_id}"
                )

            # Message loop ------
            while True:
                message_type, payload = receive_message(self.client_conn)
                if message_type is None:  # Connection closed or error
                    print(
                        f"[Peer {self.server_peer_id}] [Peer connection] Remote {self.client_addr} closed connection"
                    )
                    break

                if message_type == MESSAGE_KEEPALIVE:
                    continue

                if message_type == MESSAGE_BITFIELD:
                    self.remote_have = PieceManager.parse_bitfield(payload, self.piece_manager.num_pieces)
                    print(
                        f"[Peer {self.server_peer_id}] [Peer connection] Received bitfield from {self.remote_peer_id}: "
                        f"{sum(self.remote_have or [])} pieces available"
                    )
                    continue

                if message_type == MESSAGE_HAVE:
                    if len(payload) >= 4:
                        (piece_index,) = struct.unpack("!I", payload[:4])
                        if self.remote_have is None and self.piece_manager.num_pieces > 0:
                            self.remote_have = [False] * self.piece_manager.num_pieces
                        if self.remote_have is not None and 0 <= piece_index < len(self.remote_have):
                            self.remote_have[piece_index] = True
                        print(
                            f"[Peer {self.server_peer_id}] [Peer connection] Remote {self.remote_peer_id} now has piece {piece_index}"
                        )
                    continue

                if message_type == MESSAGE_REQUEST:
                    # Remote peer is requesting a piece from us.
                    if len(payload) >= 4:
                        (piece_index,) = struct.unpack("!I", payload[:4])
                        print(
                            f"[Peer {self.server_peer_id}] [Peer connection] Remote {self.remote_peer_id} requested piece {piece_index}"
                        )
                        if self.file_manager is not None and self.file_manager.has_piece(piece_index):
                            data = self.file_manager.read_piece(piece_index)
                            if data is not None:
                                piece_payload = struct.pack("!I", piece_index) + data
                                send_message(self.client_conn, MESSAGE_PIECE, piece_payload)
                                print(
                                    f"[Peer {self.server_peer_id}] [Peer connection] Sent piece {piece_index} to {self.remote_peer_id}"
                                )
                        else:
                            # For now, just log that we don't have the piece or no FileManager is attached.
                            print(
                                f"[Peer {self.server_peer_id}] [Peer connection] Cannot serve piece {piece_index} to {self.remote_peer_id}"
                            )
                    continue

                if message_type == MESSAGE_PIECE:
                    # We received a piece from the remote peer.
                    if len(payload) >= 4:
                        (piece_index,) = struct.unpack("!I", payload[:4])
                        data = payload[4:]
                        print(
                            f"[Peer {self.server_peer_id}] [Peer connection] Received piece {piece_index} "
                            f"(len={len(data)}) from {self.remote_peer_id}"
                        )
                        if self.file_manager is not None:
                            ok = self.file_manager.write_piece(piece_index, data)
                            if ok:
                                self.piece_manager.mark_have(piece_index)
                                print(
                                    f"[Peer {self.server_peer_id}] [Peer connection] Stored piece {piece_index} and marked as have"
                                )
                            else:
                                print(
                                    f"[Peer {self.server_peer_id}] [Peer connection] Failed to store piece {piece_index}"
                                )
                    continue

                # TODO: Handle other message types (REQUEST, PIECE)

                print(
                    f"[Peer {self.server_peer_id}] [Peer connection] Received message type {message_type} "
                    f"from {self.remote_peer_id} with payload length {0 if payload is None else len(payload)}"
                )

        except Exception as e:
            print(f"[Peer {self.server_peer_id}] [Peer connection] Error handling remote {self.client_addr}: {e}")
        finally:
            self.client_conn.close()
            print(f"[Peer {self.server_peer_id}] [Peer connection] Closed connection with remote {self.client_addr}")

class PeerServer:
    def __init__(self, ip, port, metadata, peer_id, piece_manager, file_manager: FileManager | None = None):
        self.ip = ip
        self.port = port
        self.metadata = metadata
        self.peer_id = peer_id
        self.piece_manager = piece_manager
        self.file_manager = file_manager

        self.running = False
        self.server_socket = None

    def start(self):
        """Start the server."""

        self.running = True
        thread = threading.Thread(target=self._serve, daemon=True)
        thread.start()

    def _serve(self):
        """Main server loop to accept incoming connections from other peers."""

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.server_socket = s

            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.ip, self.port))
            s.listen(50)  # TODO: Change queue size if needed

            print(f"[{self.peer_id}] [Peer server] Listening on {self.ip}:{self.port}")

            while self.running:
                conn, addr = s.accept()
                print(f"[{self.peer_id}] [Peer server] Incoming connection from {addr}")
                peer_connection = PeerConnection(
                    client_conn=conn,
                    client_addr=addr,
                    server_metadata=self.metadata,
                    server_peer_id=self.peer_id,
                    piece_manager=self.piece_manager,
                    is_incoming=True,
                    file_manager=self.file_manager,
                )
                peer_connection.start()
    
    def stop(self):
        """Stop the server."""

        print(f"[{self.peer_id}] [Peer server] Stopping...")
        
        self.running = False
        if self.server_socket:
            self.server_socket.close()


def connect_to_peer(ip: str, port: int, metadata: TorrentMetadata, peer_id: str, piece_manager: PieceManager, file_manager: FileManager | None = None) -> PeerConnection:
    """Establish an outgoing TCP connection to another peer and wrap it in a PeerConnection.

    This will connect(), perform the outgoing handshake inside PeerConnection.run(),
    send our bitfield, and then enter the message loop.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    peer_connection = PeerConnection(
        client_conn=sock,
        client_addr=(ip, port),  # TODO: Change client_addr name to remote_addr to avoid confusion
        server_metadata=metadata,  # TODO: Change server_... variable names to local_... to avoid confusion
        server_peer_id=peer_id,
        piece_manager=piece_manager,
        is_incoming=False,
        file_manager=file_manager,
    )
    peer_connection.start()
    return peer_connection

def send_message(sock: socket.socket, message_type: int, payload: bytes):
    """Send a length-prefixed message: [4-byte length][1-byte type][payload].

    The length field counts the type byte plus the payload bytes.
    """
    length = 1 + len(payload)
    header = struct.pack("!I", length)  # length of (type + payload)
    type_byte = bytes([message_type])
    sock.sendall(header + type_byte + payload)


def receive_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from the socket or return None if closed."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def receive_message(sock: socket.socket):
    """Receive one length-prefixed message and return (message_type, payload)."""
    length_packed = receive_exact(sock, 4) # First 4 bytes: length
    if not length_packed:
        return None, None
    (length,) = struct.unpack("!I", length_packed)
    body = receive_exact(sock, length)
    if not body:
        return None, None
    message_type = body[0]
    payload = body[1:]
    return message_type, payload
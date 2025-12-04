#!/usr/bin/env python3
import socket
import threading
import struct

MESSAGE_HANDSHAKE = 1

class TorrentMetadata:
    def __init__(self):
        self.info_hash = "my-dummy-info-hash"  # TODO: Replace with actual info hash

class PeerConnection(threading.Thread):
    def __init__(self, client_conn, client_ip, server_metadata, server_peer_id):
        super().__init__(daemon=True)

        self.client_conn = client_conn
        self.client_ip = client_ip
        self.server_metadata = server_metadata
        self.server_peer_id = server_peer_id
        self.remote_peer_id = None  # Client peer ID

    def run(self):
        print(f"[Peer server {self.server_peer_id}] [Peer connection] Started for remote peer {self.client_ip}")

        try:
            message_type, payload = receive_message(self.client_conn)
            if message_type != MESSAGE_HANDSHAKE or payload is None or len(payload) < 40:  # 20 bytes info_hash + 20 bytes peer_id, TODO change if needed
                print(f"[Peer server {self.server_peer_id}] [Peer connection] Invalid handshake from remote peer {self.client_ip}")
                return

            info_hash_bytes = payload[:20]
            remote_peer_id_bytes = payload[20:40]

            remote_info_hash = info_hash_bytes.decode("utf-8", errors="ignore").rstrip("_")
            self.remote_peer_id = remote_peer_id_bytes.decode("utf-8", errors="ignore").rstrip("_")

            print(f"[Peer server {self.server_peer_id}] [Peer connection] Got handshake from remote peer {self.remote_peer_id}, info hash: {remote_info_hash}")

            if remote_info_hash != self.server_metadata.info_hash:
                print(f"[Peer server {self.server_peer_id}] [Peer connection] Info hash mismatch, closing...")
                return

            my_info_hash_bytes = self.server_metadata.info_hash.encode("utf-8")[:20].ljust(20, b"_")  # TODO: Use real BitTorrent-style handshake message format
            my_peer_id_bytes = self.server_peer_id.encode("utf-8")[:20].ljust(20, b"_")
            handshake_payload = my_info_hash_bytes + my_peer_id_bytes

            send_message(self.client_conn, MESSAGE_HANDSHAKE, handshake_payload)
            
            print(f"[Peer server {self.server_peer_id}] [Peer connection] Handshake complete with {self.remote_peer_id}")

            # TODO: bitfield, message loop, pieces

        except Exception as e:
            print(f"[Peer server {self.server_peer_id}] [Peer connection] Error handling remote {self.client_ip}: {e}")
        finally:
            self.client_conn.close()
            print(f"[Peer server {self.server_peer_id}] [Peer connection] Closed connection with remote {self.client_ip}")

class PeerServer:
    def __init__(self, ip, port, metadata, peer_id):
        self.ip = ip
        self.port = port
        self.metadata = metadata
        self.peer_id = peer_id
        
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
                peer_connection = PeerConnection(client_conn=conn, client_ip=addr, server_metadata=self.metadata, server_peer_id=self.peer_id)
                peer_connection.start()
    
    def stop(self):
        """Stop the server."""

        print(f"[{self.peer_id}] [Peer server] Stopping...")
        
        self.running = False
        if self.server_socket:
            self.server_socket.close()


def send_message(sock: socket.socket, message_type: int, payload: bytes):
    """Send a length-prefixed message: [4-byte length][1-byte type][payload]."""
    length = 1 + len(payload)
    header = struct.pack("!I", length) + bytes([message_type])
    sock.sendall(header + payload)


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
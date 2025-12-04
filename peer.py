#!/usr/bin/env python3
import socket
import threading
import struct

MESSAGE_HANDSHAKE = 1

class TorrentMetadata:
    def __init__(self):
        self.info_hash = "my-dummy-info-hash"  # TODO: Replace with actual info hash

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
        thread = threading.Thread(target=self._serve)
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
                threading.Thread(target=self._handle_peer_connection, args=(conn, addr)).start()
    
    def stop(self):
        """Stop the server."""

        print(f"[{self.peer_id}] [Peer server] Stopping...")

        self.running = False
        if self.server_socket:
            self.server_socket.close()
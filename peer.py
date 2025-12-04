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
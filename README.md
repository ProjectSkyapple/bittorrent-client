# Simple BitTorrent Client
Final project for CS 4390 (Computer Networks)

This project implements a simple peer-to-peer BitTorrent client consisting of:

- A lightweight tracker that coordinates peers
- A multithreaded peer client capable of downloading and uploading
- Support for BitTorrent-like messages such as HANDSHAKE, BITFIELD, HAVE, REQUEST, PIECE
- A PieceManager and FileManager for tracking, writing, and verifying pieces

A peer loads a `.torrent` file, announces to the tracker, discovers peers, downloads pieces concurrently, verifies them using SHA1 hashing, and transitions into seeding mode once complete. The system runs entirely on localhost using unique port numbers to simulate multiple peers.

---

## 1. File Structure

```
bittorrent-client/
│
├── client.py             # Main peer program
├── tracker.py            # Tracker
├── peer.py               # PeerServer and PeerConnection (handles P2P messaging)
├── file_manager.py       # File I/O, piece validation, SHA1 hashing
├── torrent_metadata.py   # Parses .torrent files, computes info_hash
├── README.md             # Project documentation
```

---

## 2. How to Run

### 2.0 Install dependencies

This project requires dependences that are not built into Python 3: `bencodepy` for parsing bencoded content, `requests` for simplifying making HTTP GET requests to the tracker

```bash
pip install bencodepy
pip install requests
```

Using a Python virtual environment to run this project is recommended.

**Note:** Although the project code does not use Python type annotations, using them requires Python 3.10 or later.

### 2.1 Start the tracker

The tracker always runs on port **6969**:

```bash
python3 tracker.py
```

Expected output:

```
[TRACKER] Using fixed port 6969
```

---

### 2.2 Start a peer (seeder or leecher)

Each peer is started using:

```bash
python3 client.py LISTEN_PORT TORRENT_FILE OUTPUT_FILE
```

Where:

- **LISTEN_PORT** — unique port for this peer instance (e.g., 6881, 6882, 6883…)
- **TORRENT_FILE** — path to the `.torrent` metadata file
- **OUTPUT_FILE** — location where the downloaded data will be stored
  - If this file already contains valid SHA1-verified pieces, the peer starts as a **seeder**
  - Otherwise, it behaves as a **leecher**

---

### 2.3 Example

Seeder (must have the complete file) (the torrent file for _Alice_ is located in the `test_leecher_files` directory):

```bash
python3 client.py 6881 ./test_leecher_files/alice.torrent ./test_seeder_files/alice.txt
```

Leecher:

```bash
python3 client.py 6882 ./test_leecher_files/alice.torrent ./alice_download-peer2
```

---

### 2.4 Another example: Running multiple peers

To simulate a swarm:

```bash
python3 client.py 6883 ./test_leecher_files/alice.torrent ./peer3_copy.txt
python3 client.py 6884 ./test_leecher_files/alice.torrent ./peer4_copy.txt
```

Each instance:

- Announces to the tracker
- Discovers other peers
- Exchanges bitfields
- Requests or uploads pieces simultaneously


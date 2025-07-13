import os
import hashlib
import requests
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)


self_ip = "your IP"


peer_list = [
    "Node 2/Your Friend IP"
]

class P2PNetwork:
    def __init__(self, self_ip, peer_list):
        self.self_ip = self_ip
        self.peers = set(peer_list)
        self.BLOCKCHAIN_DIR = "./blockchain_files"
        os.makedirs(self.BLOCKCHAIN_DIR, exist_ok=True)
        self.register_to_peers()
        self.start_periodic_sync()

    def register_to_peers(self):
        for peer in list(self.peers):
            try:
                requests.post(f"{peer}/admin/register-peer", json={"peer": self.self_ip}, timeout=5)
                print(f"Registered with {peer}")
            except Exception as e:
                print(f"Gagal register ke {peer}: {e}")

    def register_node(self, peer_url):
        if peer_url not in self.peers and peer_url != self.self_ip:
            self.peers.add(peer_url)
            print(f"Peer registered: {peer_url}")

    def start_periodic_sync(self):
        self.sync_chain_and_files()
        threading.Timer(60, self.start_periodic_sync).start()

    def sync_chain_and_files(self):
        for peer in list(self.peers):
            try:
                self.receive_blockchain_from_peer(peer)
                self.send_blockchain_to_peer(peer)
            except Exception as e:
                print(f"Failed to sync with {peer}: {e}")

    def send_blockchain_to_peer(self, peer_url):
        file_name = "blockchain.json"
        file_path = os.path.join(self.BLOCKCHAIN_DIR, file_name)
        if not os.path.exists(file_path):
            return
        try:
            with open(file_path, 'r') as file:
                file_data = file.read()
                file_hash = hashlib.sha256(file_data.encode()).hexdigest()

            response = requests.post(
                f"{peer_url}/admin/receive-blockchain",
                json={
                    'file_name': file_name,
                    'file_data': file_data,
                    'file_hash': file_hash
                },
                timeout=10
            )
            if response.status_code == 200:
                print(f"{file_name} sent to {peer_url}")
        except Exception as e:
            print(f"Error sending blockchain to {peer_url}: {e}")

    def receive_blockchain_from_peer(self, peer_url):
        try:
            response = requests.get(f"{peer_url}/admin/get-blockchain-file", timeout=10)
            if response.status_code != 200:
                return
            data = response.json()
            file_name = data.get('file_name')
            file_data = data.get('file_data')
            received_hash = data.get('file_hash')
            calculated_hash = hashlib.sha256(file_data.encode()).hexdigest()
            if calculated_hash != received_hash:
                return
            file_path = os.path.join(self.BLOCKCHAIN_DIR, file_name)
            with open(file_path, 'w') as file:
                file.write(file_data)
            print(f"{file_name} updated from {peer_url}")
        except Exception as e:
            print(f"Error receiving blockchain from {peer_url}: {e}")

    def list_peers(self):
        return list(self.peers)

p2p_network = P2PNetwork(self_ip, peer_list)

@app.route('/admin/get-blockchain-file', methods=['GET'])
def get_blockchain_file():
    file_name = "blockchain.json"
    file_path = os.path.join(p2p_network.BLOCKCHAIN_DIR, file_name)
    if not os.path.exists(file_path):
        return jsonify({"error": f"{file_name} not found"}), 404
    with open(file_path, 'r') as file:
        file_data = file.read()
        file_hash = hashlib.sha256(file_data.encode()).hexdigest()
    return jsonify({
        'file_name': file_name,
        'file_data': file_data,
        'file_hash': file_hash
    }), 200

@app.route('/admin/receive-blockchain', methods=['POST'])
def receive_blockchain():
    data = request.json
    file_name = data.get('file_name')
    file_data = data.get('file_data')
    received_hash = data.get('file_hash')
    calculated_hash = hashlib.sha256(file_data.encode()).hexdigest()
    if calculated_hash != received_hash:
        return jsonify({"error": "Invalid file hash"}), 400
    file_path = os.path.join(p2p_network.BLOCKCHAIN_DIR, file_name)
    with open(file_path, 'w') as file:
        file.write(file_data)
    return jsonify({"message": f"{file_name} received and saved"}), 200

@app.route('/admin/register-peer', methods=['POST'])
def register_peer():
    data = request.json
    peer = data.get("peer")
    if peer:
        p2p_network.register_node(peer)
        return jsonify({"message": f"Peer {peer} registered"}), 200
    return jsonify({"error": "Peer URL missing"}), 400

@app.route('/admin/peers', methods=['GET'])
def list_peers():
    return jsonify({"self_ip": self_ip, "peers": p2p_network.list_peers()})

if __name__ == '__main__':
    host_ip = self_ip.split('//')[1].split(':')[0]
    port = int(self_ip.split(':')[-1])
    print(f"Running node at {self_ip}")
    print(f"Connected peers: {peer_list}")
    app.run(host=host_ip, port=port)
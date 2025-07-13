# E-Voting System with Zytherion Blockchain (v0.10)

This is the **v0.10 alpha** version of a decentralized E-Voting system powered by the **Zytherion Blockchain**. It integrates blockchain concepts such as Proof-of-Work (PoW), AES encryption, Zero Knowledge Proofs (ZKP), and Homomorphic Encryption to ensure data integrity and secure voting.

## 🔧 Features

- ✅ Blockchain-based vote ledger
- 🔒 AES-encrypted candidate data
- 🧠 Homomorphic encryption for secure tallying
- 🔍 ZKP for anonymous proof of vote integrity
- 👨‍⚖️ Admin dashboard & vote monitoring
- 🧱 Block mining mechanism via CLI or web interface

## 🛠️ Setup Instructions

### 1. Clone or Download
```bash
git clone https://github.com/<your-username>/e-voting-zytherion.git
cd e-voting-zytherion
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the App
```bash
python app.py
```

### 4. Access in Browser
- User Login: `http://127.0.0.1:5000/login`
- Admin Login: `http://127.0.0.1:5000/admin_login`

## 📁 Project Structure

- `app.py`: Flask server entry point
- `blockchain/`: Core blockchain logic (PoW, AES, ZKP, etc)
- `templates/`: HTML templates for login, dashboard
- `static/`: Stylesheets and images
- `blockchain_files/`: JSON file containing blockchain data
- `mining.py`: Manual mining script for testing

## ⚠️ Disclaimer

This version is still under **heavy development** and should be used for educational or testing purposes only.

---

## ⛏️ Mining Blocks (Starter Instructions)

To begin mining blocks and contributing to the Zytherion blockchain:

### 1. Open the Mining Script
Open and run the file:

```bash
python mining.py
```

By default, the miner will generate **up to 25 blocks**.  
You can modify the maximum block number in:

```bash
blockchain/blockchain.py
```

Look for a variable like:
```python
MAX_BLOCKS = 25
```

You may change the number if you want to simulate more blocks.

---

## 🌐 IP Configuration for P2P Nodes

To connect this node with other nodes (Node 1 ↔ Node 2), you must manually edit the file:

```bash
utils/p2p_network.py
```

And set:
```python
self_ip = "your IP"
peer_list = [
    "Node 2/Your Friend IP"
]
```

Make sure both machines are connected in the same network (LAN or public IP), and the ports are open.



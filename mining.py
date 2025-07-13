import time
import threading
import schedule
from flask import Flask, jsonify
from blockchain.block import Block
from blockchain.blockchain import Blockchain
import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Initialize Flask app for mining
app = Flask(__name__)

# Load blockchain from the main application
BLOCKCHAIN_FILE = "./blockchain_files/blockchain.json"
MINING_DIFFICULTY = 4

# Initialize blockchain
blockchain = Blockchain(difficulty=MINING_DIFFICULTY)
blockchain.load_from_file(BLOCKCHAIN_FILE)

@app.route('/mine', methods=['POST'])
def mine():
    """
    Mine a new block and add it to the blockchain.
    """
    if len(blockchain.chain) >= blockchain.MAX_BLOCKS:
        print(Fore.YELLOW + "⚠ Maximum number of blocks reached.")
        return jsonify({"message": "Maximum number of blocks reached."}), 400

    # Create a new block
    new_index = len(blockchain.chain)
    new_block = Block(
        index=new_index,
        previous_hash=blockchain.chain[-1].hash,
        data={
            "message": f"Mined block at {time.ctime()}",
            "validator": "Hexaforge"
        }
    )

    # Mining in progress message
    print(Style.BRIGHT + Fore.BLUE + f"⛏ Mining block {new_index}...")

    # Mine the block
    new_block.mine_block(blockchain.difficulty)

    # Add the new block to the chain
    blockchain.add_block(new_block)
    print(Fore.GREEN + f"✅ New block mined with hash: {new_block.hash}")

    return jsonify({
        "message": "Block mined successfully.",
        "block": new_block.to_dict()
    }), 201

@app.route('/get_chain', methods=['GET'])
def get_chain():
    """
    Return the entire blockchain.
    """
    print(Fore.CYAN + "🔗 Sending full blockchain...")
    return jsonify({
        "chain": [block.to_dict() for block in blockchain.chain]
    }), 200

def start_automatic_mining():
    """
    Schedule automatic mining every 1 minute.
    """
    def mine_blocks():
        try:
            print(Fore.MAGENTA + "🔄 Attempting automatic mining...")
            response = requests.post("http://localhost:5001/mine")
            if response.status_code == 201:
                print(Fore.CYAN + "✔ Automatic mining successful.")
            else:
                print(Fore.YELLOW + f"⚠ Automatic mining failed. Status: {response.status_code}")
        except Exception as e:
            print(Fore.RED + f"❌ Failed to mine block: {e}")

    # Schedule mining every 1 minute
    schedule.every(40).seconds.do(mine_blocks)

    # Run scheduler in a separate thread
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)

    threading.Thread(target=run_scheduler, daemon=True).start()

if __name__ == '__main__':
    print(Fore.LIGHTBLUE_EX + Style.BRIGHT + "🚀 Starting Mining Server on http://localhost:5001")
    
    # Start automatic mining
    start_automatic_mining()

    # Run the mining server on port 5001
    app.run(host='0.0.0.0', port=5001, debug=True)

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash, session
from blockchain.blockchain import Blockchain
from blockchain.block import Block
from utils.mailjet_api import MailJetAPI
from utils.sha256_hash import sha256_hash
from config import Config
import hashlib
from blockchain.aes_encryption import decrypt_data_aes
import os
import json
import time
import random
import base64
from utils.txhgen import generate_tx_hash

# Initialize Blueprint
user_bp = Blueprint('user', __name__)

BLOCKCHAIN_DIR = "./blockchain_files"

# Initialize Blockchain, ZKP, Homomorphic Encryption, and MailJet API
blockchain = Blockchain(Config.BLOCKCHAIN_DIFFICULTY)
mailjet = MailJetAPI(Config.MAILJET_API_KEY, Config.MAILJET_API_SECRET)

validation_requests = []
@user_bp.route('/', methods=['GET', 'POST'])
def login():
    """User login using transaction hash."""
    # Load blockchain from file
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    
    if request.method == 'POST':
        # Get transaction hash from form
        tx_hash = request.form.get('tx_hash')
        
        # Debug: Print the received TX Hash
        print(f"Received TX Hash: {tx_hash}")
        
        # Search for the voter in the blockchain
        found_voter = None
        for block in blockchain.chain:
            if 'voters' in block.data:
                for voter in block.data['voters']:
                    if voter['tx_hash'] == tx_hash and voter['status'] == "Validated":
                        # Decrypt voter data using AES key
                        try:
                            aes_key = base64.b64decode(voter.get("aes_key"))
                            decrypted_data = {
                                "voter_id": decrypt_data_aes(aes_key, voter["encrypted_data"]["voter_id"]),
                                "nim": decrypt_data_aes(aes_key, voter["encrypted_data"]["nim"]),
                                "name": decrypt_data_aes(aes_key, voter["encrypted_data"]["name"]),
                                "dob": decrypt_data_aes(aes_key, voter["encrypted_data"]["dob"]),
                                "email": decrypt_data_aes(aes_key, voter["encrypted_data"]["email"])
                            }
                            # Store decrypted data in a variable
                            voter["decrypted_data"] = decrypted_data
                            found_voter = voter
                            break
                        except Exception as e:
                            print(f"Error decrypting voter data: {e}")
                            flash("Failed to decrypt voter data.", "danger")
                            return redirect(url_for('user.login'))
        
        # If voter is found, save decrypted data to session and redirect
        if found_voter:
            print(f"Voter Found: {found_voter['decrypted_data']}")
            session['user_data'] = found_voter['decrypted_data']
            session['tx_hash'] = tx_hash  # Save TX Hash in session
            flash("Login successful!", "success")
            return redirect(url_for('user.dashboard', tx_hash=tx_hash))
        else:
            print("Voter not found or invalid TX Hash.")
            flash("Invalid transaction hash or voter not validated.", "danger")
    
    # Render login page
    return render_template('user/login.html')

@user_bp.route('/dashboard', methods=['GET'])
def dashboard():
    """Display user dashboard with voter details and candidates."""
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    user_data = None
    candidates = []
    zth_amount = 0
    tx_hash = None  # voter_tx
    
    # ✅ Ambil voter pertama yang statusnya Validated
    for block in blockchain.chain:
        if 'voters' in block.data:
            for voter in block.data['voters']:
                if voter.get('status') == "Validated":
                    tx_hash = voter.get("tx_hash")
                    aes_key = base64.b64decode(voter.get("aes_key"))
                    decrypted_data = {
                        "voter_id": decrypt_data_aes(aes_key, voter["encrypted_data"]["voter_id"]),
                        "nim": decrypt_data_aes(aes_key, voter["encrypted_data"]["nim"]),
                        "name": decrypt_data_aes(aes_key, voter["encrypted_data"]["name"]),
                        "dob": decrypt_data_aes(aes_key, voter["encrypted_data"]["dob"]),
                        "email": decrypt_data_aes(aes_key, voter["encrypted_data"]["email"])
                    }
                    user_data = decrypted_data
                    zth_amount = voter.get('zth_amount', 0)
        
        if "candidates" in block.data:
            for candidate in block.data["candidates"]:
                    try:
                        # Extract candidate data
                        tx_hash = candidate.get("tx_hash", "Unknown")
                        aes_key = base64.b64decode(candidate.get("aes_key", ""))
                        encrypted_candidate_number = candidate.get("encrypted_candidate_number", {})
                        encrypted_candidate_name = candidate.get("encrypted_candidate_name", {})
                        encrypted_photo_hash = candidate.get("encrypted_photo_hash", {})  # Include encrypted photo hash
                        photo_base64 = candidate.get("photo_base64", "")

                        # Decrypt candidate data
                        decrypted_candidate_number = decrypt_data_aes(
                            aes_key,
                            encrypted_candidate_number
                        )
                        decrypted_candidate_name = decrypt_data_aes(
                            aes_key,
                            encrypted_candidate_name
                        )

                        # Append candidate data to list
                        candidates.append({
                            "tx_hash": tx_hash,
                            "candidate_number": decrypted_candidate_number,
                            "candidate_name": decrypted_candidate_name,
                            "encrypted_photo_hash": encrypted_photo_hash,  # Include encrypted photo hash
                            "photo_base64": photo_base64  # Use original photo for display
                        })
                    except Exception as e:
                        print(f"Error processing candidate data: {e}")
                        continue

    # Redirect to login if user data is not found
    if not user_data:
        flash("User data not found.")
        return redirect(url_for('user.login'))

    # Extract voter details
    voter_id = user_data.get('voter_id', 'N/A')
    nim = user_data.get('nim', 'N/A')
    name = user_data.get('name', 'N/A')
    dob = user_data.get('dob', 'N/A')
    email = user_data.get('email', 'N/A')

    return render_template(
        'user/dashboard.html',
        user=user_data,
        voter_id=voter_id,
        nim=nim,
        name=name,
        dob=dob,
        email=email,
        zth_amount=zth_amount,  # Include ZTH balance
        candidates=candidates,
        tx_hash=tx_hash
    )

@user_bp.route('/vote', methods=['POST'])
def vote():
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))

    voter_data = None
    for block in blockchain.chain:
        if "voters" in block.data:
            for voter in block.data["voters"]:
                if voter.get("status") == "Validated" and not voter.get("has_voted", False):
                    voter_data = voter
                    break
        if voter_data:
            break

    if not voter_data:
        flash("No validated or available voters found.")
        return redirect(url_for("user.dashboard"))

    voter_tx = voter_data["tx_hash"]


    candidate_data = None
    for block in blockchain.chain:
        if "candidates" in block.data:
            for candidate in block.data["candidates"]:
                candidate_data = candidate
                break
        if candidate_data:
            break

    if not candidate_data:
        flash("No candidates found in blockchain.")
        return redirect(url_for("user.dashboard"))

    candidate_tx = candidate_data["tx_hash"]


    voting_price = random.uniform(0.95, 0.99)
    gas_fee = 0.001
    total_fee = voting_price + gas_fee


    if voter_data.get("zth_amount", 0) < total_fee:
        flash(f"Insufficient balance. Required: {total_fee:.8f} ZTH")
        return redirect(url_for("user.dashboard"))


    voter_data["zth_amount"] -= total_fee
    voter_data["has_voted"] = True

    # Add choice-candidate to voter data
    choice_candidate = request.form.get('candidate_choice')
    voter_data["choice-candidate"] = choice_candidate  # Store selected candidate number

    transaction = {
        "tx_hash": generate_tx_hash({
            "voter_tx": voter_tx,
            "candidate_tx": candidate_tx,
            "timestamp": time.time(),
            "amount": voting_price,
            "gas_fee": gas_fee,
            "voting_fee": voting_price  # Include voting fee here
        }),
        "from": voter_tx,
        "to": candidate_tx,
        "amount": voting_price,
        "timestamp": time.time(),
        "gas_fee": gas_fee,
        "voting_fee": voting_price,  # Store voting fee
        "status": "Success"
    }

    available_blocks = [block for block in blockchain.chain if block.index > 0]
    if not available_blocks:
        flash("No blocks available to record the transaction.")
        return redirect(url_for("user.dashboard"))

    selected_block = random.choice(available_blocks)
    if "transactions" not in selected_block.data:
        selected_block.data["transactions"] = []
    selected_block.data["transactions"].append(transaction)

    try:
        blockchain.save_to_file("./blockchain_files/blockchain.json")
    except Exception as e:
        flash(f"Error saving blockchain: {str(e)}")
        return redirect(url_for("user.dashboard"))

    os.makedirs("transactions", exist_ok=True)
    with open(f"transactions/{transaction['tx_hash']}.json", "w") as f:
        json.dump(transaction, f, indent=4)


    return redirect(url_for("user.transactions", voter_tx=voter_tx))

@user_bp.route('/transactions', methods=['GET', 'POST'])
def transactions():
    voter_tx = request.args.get('voter_tx')

    if request.method == 'POST':
        tx_hash = request.form.get('tx_hash')
        if not tx_hash:
            return jsonify({'message': 'Missing tx_hash'}), 400

        file_path = f'transactions/{tx_hash}.json'
        if not os.path.exists(file_path):
            return jsonify({'message': 'Transaction file not found'}), 404

        try:
            # Load and update transaction status
            with open(file_path, 'r') as f:
                transaction = json.load(f)
            transaction["status"] = "Success"

            # Save updated transaction
            with open(file_path, 'w') as f:
                json.dump(transaction, f)

            # Update blockchain with the transaction
            blockchain_file = os.path.join(os.getcwd(), 'blockchain_files/blockchain.json')
            with open(blockchain_file, 'r') as f:
                chain_data = json.load(f)

            chosen_block = random.choice(chain_data)
            if 'data' not in chosen_block or not isinstance(chosen_block['data'], dict):
                chosen_block['data'] = {}
            if 'transactions' not in chosen_block['data'] or not isinstance(chosen_block['data']['transactions'], list):
                chosen_block['data']['transactions'] = []

            chosen_block['data']['transactions'].append(transaction)

            # Save updated blockchain
            with open(blockchain_file, 'w') as f:
                json.dump(chain_data, f, indent=4)

            flash("Transaction successful and recorded.")
            return redirect(url_for('user.ledger'))
        except Exception as e:
            return jsonify({'message': f'Error processing transaction: {str(e)}'}), 500

    # GET: Display all transactions for the voter
    txs = []
    if os.path.exists('transactions'):
        for file in os.listdir('transactions'):
            with open(f'transactions/{file}', 'r') as f:
                tx = json.load(f)
                if tx['from'] == voter_tx:
                    # Add choice_candidate and candidate_name to the transaction
                    choice_candidate = None
                    candidate_name = "Unknown"
                    for block in blockchain.chain:
                        if "voters" in block.data:
                            for voter in block.data["voters"]:
                                if voter.get("tx_hash") == tx.get("from"):
                                    choice_candidate = voter.get("choice-candidate", "Unknown")
                                    break

                        if "candidates" in block.data:
                            for candidate in block.data["candidates"]:
                                if candidate.get("tx_hash") == tx.get("to"):
                                    try:
                                        aes_key = base64.b64decode(candidate.get("aes_key", ""))
                                        candidate_name = decrypt_data_aes(aes_key, candidate.get("encrypted_candidate_name"))
                                    except Exception as e:
                                        print(f"Error decrypting candidate name: {str(e)}")
                                    break

                    tx["choice_candidate"] = choice_candidate
                    tx["candidate_name"] = candidate_name
                    txs.append(tx)

    return render_template('user/transaction.html', transactions=txs, voter_tx=voter_tx)

@user_bp.route('/Ledger_of_transaction', methods=['GET'])
def ledger():
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    ledger_list = []

    # Ambil data transaksi dari tiap block
    for block in blockchain.chain:
        if isinstance(block.data, dict) and 'transactions' in block.data:
            transactions = block.data['transactions']
            for tx in transactions:
                # Cari nama kandidat berdasarkan tx["to"]
                candidate_name = "Unknown"
                decrypted_candidate_number = "Unknown"
                for blk in blockchain.chain:
                    if "candidates" in blk.data:
                        for candidate in blk.data["candidates"]:
                            if candidate.get("tx_hash") == tx.get("to"):
                                try:
                                    aes_key = base64.b64decode(candidate.get("aes_key", ""))
                                    candidate_name = decrypt_data_aes(aes_key, candidate.get("encrypted_candidate_name"))
                                    
                                    # Decrypt candidate number
                                    encrypted_candidate_number = candidate.get("encrypted_candidate_number", {})
                                    decrypted_candidate_number = decrypt_data_aes(
                                        aes_key,
                                        encrypted_candidate_number
                                    )
                                except Exception as e:
                                    print(f"Error decrypting candidate data: {str(e)}")
                                break

                # Get the choice-candidate from voters
                choice_candidate = None
                for block in blockchain.chain:
                    if "voters" in block.data:
                        for voter in block.data["voters"]:
                            if voter.get("tx_hash") == tx.get("from"):
                                choice_candidate = voter.get("choice-candidate", "Unknown")
                                break

                ledger_list.append({
                    'tx_hash': tx.get('tx_hash'),
                    'block': block.index,  # Include the block number
                    'from': tx.get('from'),
                    'to': tx.get('to'),
                    'amount': tx.get('amount'),
                    'timestamp': tx.get('timestamp'),
                    'gas_fee': tx.get('gas_fee'),
                    'voting_fee': tx.get('voting_fee'),  # Display the voting fee
                    'candidate_name': candidate_name,
                    'candidate_number': decrypted_candidate_number,  # Add decrypted candidate number
                    'choice_candidate': choice_candidate  # Show the selected candidate number
                })

    return render_template('user/ledger.html', ledger=ledger_list)


@user_bp.route('/results', methods=['GET'])
def results():
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    votes = {}
    total_votes = 0

    # Iterate through blocks and count votes based on choice-candidate
    for block in blockchain.chain:
        txs = block.data.get('transactions', [])
        if isinstance(txs, dict):  # If single transaction
            txs = [txs]

        for tx in txs:
            if tx.get('status') == 'Success':
                choice_candidate = None
                for block in blockchain.chain:
                    if "voters" in block.data:
                        for voter in block.data["voters"]:
                            if voter.get("tx_hash") == tx.get('from'):
                                choice_candidate = voter.get("choice-candidate")
                                break
                if choice_candidate:
                    votes[choice_candidate] = votes.get(choice_candidate, 0) + 1
                    total_votes += 1

    results_list = []
    for candidate_num, count in votes.items():
        percent = (count / total_votes) * 100 if total_votes else 0
        results_list.append({
            'candidate_number': candidate_num,
            'votes': count,
            'percent': round(percent, 2)
        })

    return render_template('user/results.html', results=results_list)



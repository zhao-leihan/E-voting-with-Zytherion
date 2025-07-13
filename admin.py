from flask import Blueprint, render_template, request, redirect, url_for, jsonify, flash, session, Flask
from flask_session import Session
from blockchain.blockchain import Blockchain
from utils.mailjet_api import MailJetAPI
from blockchain.aes_encryption import generate_aes_key, encrypt_data_aes, decrypt_data_aes, decrypt_admin_data
from config import Config
import random
from random import choice
import time 
import string
import base64

from utils.txhgen import generate_tx_hash  # Import helper function
import os
import hashlib
from blockchain.homomorphic_encryption import encrypt_data_phe, decrypt_data_phe,get_public_key, get_private_key
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# Initialize Blueprint
admin_bp = Blueprint('admin', __name__)

BLOCKCHAIN_DIR = "./blockchain_files"

admins = {}

# Initialize Blockchain, MailJet API, and AES Encryption
blockchain = Blockchain(Config.BLOCKCHAIN_DIFFICULTY)
mailjet = MailJetAPI(Config.MAILJET_API_KEY, Config.MAILJET_API_SECRET)
blockchain = Blockchain(difficulty=4)
app = Flask(__name__)
# Konfigurasi Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key'  # Ganti dengan secret key yang aman
app.config['SESSION_TYPE'] = 'filesystem'  # Simpan sesi di file sistem
app.config['SESSION_PERMANENT'] = False  # Nonaktifkan sesi permanen

# Inisialisasi Flask-Session
Session(app)

public_key = get_public_key()
private_key = get_private_key()

# Temporary storage for pending voter data
pending_voters = {}
random.seed(time.time())

@admin_bp.route('/', methods=['GET', 'POST'])
def admin_login():
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    """Login as an admin."""
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Check if admin exists in blockchain
        for block in blockchain.chain:
            if "admins" in block.data:
                for admin in block.data["admins"]:
                    # Skip old blocks without aes_key
                    if "aes_key" not in admin:
                        continue

                    # Decrypt username
                    try:
                        aes_key = base64.b64decode(admin["aes_key"])
                        encrypted_username = admin["encrypted_username"]
                        decrypted_username = decrypt_data_aes(
                            aes_key,
                            {
                                "iv": encrypted_username["iv"],
                                "ciphertext": encrypted_username["ciphertext"]
                            }
                        )
                        if decrypted_username == username:
                            # Verify password
                            hashed_password = admin["hashed_password"]
                            if check_password_hash(hashed_password, password):
                                session['admin_logged_in'] = True
                                session['admin_username'] = username
                                flash("Login successful!", "success")
                                return redirect(url_for('admin.admin_dashboard'))
                            else:
                                flash("Invalid password.", "danger")
                                return redirect(url_for('admin.admin_login'))
                    except Exception as e:
                        print(f"Error decrypting username: {e}")
                        continue

        flash("Admin not found.", "danger")
        return redirect(url_for('admin.admin_login'))

    # Render login form
    return render_template('admin/admin_login.html')

@admin_bp.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    """Register a new admin."""
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))

    if request.method == 'POST':
        # Extract form data
        username = request.form['username']
        password = request.form['password']
        user_ip = request.remote_addr  # Get the user's IP address

        # Validate unique username, password, and IP across all blocks
        for block in blockchain.chain:
            if "admins" in block.data:
                for admin in block.data["admins"]:
                    # Skip old blocks without aes_key
                    if "aes_key" not in admin:
                        continue

                    try:
                        # Decrypt username
                        aes_key = base64.b64decode(admin["aes_key"])
                        encrypted_username = admin["encrypted_username"]
                        decrypted_username = decrypt_data_aes(
                            aes_key,
                            {
                                "iv": encrypted_username["iv"],
                                "ciphertext": encrypted_username["ciphertext"]
                            }
                        )
                        if decrypted_username == username:
                            flash("Username already exists. Please choose another.", "danger")
                            return redirect(url_for('admin.admin_register'))

                        # Check for duplicate password (optional)
                        encrypted_password = admin["encrypted_password"]
                        decrypted_password = decrypt_data_aes(
                            aes_key,
                            {
                                "iv": encrypted_password["iv"],
                                "ciphertext": encrypted_password["ciphertext"]
                            }
                        )
                        if decrypted_password == password:
                            flash("Password already exists. Please choose another.", "danger")
                            return redirect(url_for('admin.admin_register'))

                        # Decrypt and check for duplicate IP
                        encrypted_ip = admin.get("encrypted_ip")
                        if encrypted_ip:
                            decrypted_ip = decrypt_data_aes(
                                aes_key,
                                {
                                    "iv": encrypted_ip["iv"],
                                    "ciphertext": encrypted_ip["ciphertext"]
                                }
                            )
                            if decrypted_ip == user_ip:
                                flash("IP address already registered. Only one registration allowed per IP.", "danger")
                                return redirect(url_for('admin.admin_register'))
                    except Exception as e:
                        print(f"Error validating admin data: {e}")
                        continue

        # Select a random block (excluding genesis block)
        available_blocks = [block for block in blockchain.chain if block.index != 0]  # Exclude genesis block
        if not available_blocks:
            flash("No available blocks for registration. Please try again later.", "danger")
            return redirect(url_for('admin.admin_register'))

        selected_block = random.choice(available_blocks)

        # Generate AES key for encryption
        aes_key = generate_aes_key()

        # Encrypt username, password, and IP
        encrypted_username = encrypt_data_aes(aes_key, username)
        encrypted_password = encrypt_data_aes(aes_key, password)
        encrypted_ip = encrypt_data_aes(aes_key, user_ip)  # Encrypt the IP address

        # Hash the password (optional, for additional security)
        hashed_password = generate_password_hash(password)

        # Generate TX Hash for the admin
        tx_hash = generate_tx_hash({
            "username": username,
            "password": hashed_password,
            "ip_address": user_ip  # Include IP in TX hash
        })

        # Prepare admin data
        admin_data = {
            "tx_hash": tx_hash,
            "aes_key": base64.b64encode(aes_key).decode(),  # Store AES key securely
            "encrypted_username": encrypted_username,
            "encrypted_password": encrypted_password,
            "encrypted_ip": encrypted_ip,  # Store encrypted IP address
            "hashed_password": hashed_password,  # Optional, for additional security
            "zth_amount": 0,  # Initialize ZTH amount to 0
            "transactions": []  # Initialize transactions array for this admin
        }

        # Add admin to the selected block
        if "admins" not in selected_block.data:
            selected_block.data["admins"] = []
        selected_block.data["admins"].append(admin_data)

        # Generate a unique system address (0xSystem)
        system_address = f"0x{hashlib.sha256(b'System').hexdigest()[:8]}"

        # Create initial balance transaction for the admin
        initial_balance_transaction = {
            "tx_hash": generate_tx_hash({
                "from": system_address,
                "to": tx_hash,  # Use admin's TX Hash as the "address"
                "amount": 1,  # 1 ZTH
                "timestamp": time.time(),
                "gas_fee": 0  # No gas fee for initial balance
            }),
            "from": system_address,
            "to": tx_hash,
            "amount": 1,
            "timestamp": time.time(),
            "gas_fee": 0
        }

        # Add the initial balance transaction to the admin's transactions array
        admin_data["transactions"].append(initial_balance_transaction)

        # Update admin's ZTH amount based on the transaction
        admin_data["zth_amount"] += initial_balance_transaction["amount"]

        # Save updated blockchain to file
        blockchain.save_to_file("./blockchain_files/blockchain.json")
        print(f"Admin registered with TX Hash: {tx_hash} in block {selected_block.index}")

        flash("Admin registered successfully!", "success")
        return redirect(url_for('admin.admin_login'))

    # Render registration form
    return render_template('admin/admin_register.html')

@admin_bp.route('/dashboard', methods=['GET'])
def admin_dashboard():
    """Render the admin dashboard."""
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
    
    # Check if admin is logged in
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        flash("You need to log in to access the dashboard.", "danger")
        return redirect(url_for('admin.admin_login'))

    # Get the current admin's username from the session
    admin_username = session.get('admin_username', 'Admin')

    # Decrypt all admin data from the blockchain
    decrypted_admins = []
    for block in blockchain.chain:
        if "admins" in block.data:
            for admin in block.data["admins"]:
                try:
                    decrypted_admin = decrypt_admin_data(admin, block.index)
                    if decrypted_admin:
                        decrypted_admins.append(decrypted_admin)
                except Exception as e:
                    print(f"Error decrypting admin data: {e}")
                    continue

    # Calculate ZTH balance for each admin
    admin_balances = {}
    for block in blockchain.chain:
        if "transactions" in block.data:
            for transaction in block.data["transactions"]:
                recipient = transaction.get("to")  # The recipient of the transaction
                amount = transaction.get("amount", 0)  # Amount transferred
                if recipient not in admin_balances:
                    admin_balances[recipient] = 0
                admin_balances[recipient] += amount

    # Add ZTH balances to decrypted admin data
    for admin in decrypted_admins:
        admin_tx_hash = admin["tx_hash"]  # Admin's address (TX Hash)
        admin["zth_balance"] = admin_balances.get(admin_tx_hash, 0)  # Default to 0 if no balance

    # Find the block where the current admin is registered (if any)
    your_block = None
    your_zth_balance = 0
    for block in blockchain.chain:
        if "admins" in block.data:
            for admin in block.data["admins"]:
                try:
                    aes_key = base64.b64decode(admin["aes_key"])
                    encrypted_username = admin["encrypted_username"]
                    decrypted_username = decrypt_data_aes(
                        aes_key,
                        {
                            "iv": encrypted_username["iv"],
                            "ciphertext": encrypted_username["ciphertext"]
                        }
                    )
                    if decrypted_username == admin_username:
                        # Only store the block index
                        your_block = block.index
                        # Get the admin's ZTH balance from zth_amount
                        your_zth_balance = admin.get("zth_amount", 0)  # Use zth_amount if available, else default to 0
                        break
                except Exception as e:
                    print(f"Error decrypting username: {e}")
                    continue

    return render_template(
        'admin/dashboard.html',
        admin_username=admin_username,
        your_block=your_block,
        your_zth_balance=your_zth_balance,
        admins=decrypted_admins
    )

@admin_bp.route('/register', methods=['GET', 'POST'])
def register_voter():
    """Register a new voter."""
    global pending_voters

    if request.method == 'POST':
        # Get form data
        nim = request.form['nim']
        name = request.form['name']
        dob = request.form['dob']
        email = request.form['email']

        print(f"Input Data - NIM: {nim}, Name: {name}, DOB: {dob}, Email: {email}")  # Debug log

        # Generate random Voter ID
        voter_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        print(f"Generated Voter ID: {voter_id}")  # Debug log

        # Hash sensitive data to numeric values
        hashed_data = {
            "voter_id": int(hashlib.sha256(voter_id.encode()).hexdigest(), 16) % 10**8,
            "nim": int(hashlib.sha256(nim.encode()).hexdigest(), 16) % 10**8,
            "name": int(hashlib.sha256(name.encode()).hexdigest(), 16) % 10**8,
            "dob": int(hashlib.sha256(dob.encode()).hexdigest(), 16) % 10**8,
            "email": int(hashlib.sha256(email.encode()).hexdigest(), 16) % 10**8
        }
        print(f"Hashed Data: {hashed_data}")  # Debug log

        # Generate AES key
        aes_key = generate_aes_key()
        print(f"AES Key Generated: {base64.b64encode(aes_key).decode()}")  # Debug log

        # Encrypt data using AES
        encrypted_data = {
            "voter_id": encrypt_data_aes(aes_key, str(hashed_data["voter_id"])),
            "nim": encrypt_data_aes(aes_key, str(hashed_data["nim"])),
            "name": encrypt_data_aes(aes_key, name),
            "dob": encrypt_data_aes(aes_key, dob),
            "email": encrypt_data_aes(aes_key, email)
        }
        print(f"Encrypted Data: {encrypted_data}")  # Debug log

        # Generate TX Hash based on voter data
        tx_hash = generate_tx_hash({
            "voter_id": voter_id,
            "nim": nim,
            "name": name,
            "dob": dob,
            "email": email
        })
        print(f"Generated TX Hash: {tx_hash}")  # Debug log

        # Randomly select an available block (excluding genesis block)
        available_blocks = [block for block in blockchain.chain if block.index > 0]
        if not available_blocks:
            flash("No available blocks for registration. Please try again later.", "danger")
            return redirect(url_for('admin.admin_dashboard'))

        selected_block = random.choice(available_blocks)
        print(f"Selected Block Index: {selected_block.index}")  # Debug log

        # Add voter data to the selected block
        if "voters" not in selected_block.data:
            selected_block.data["voters"] = []
        selected_block.data["voters"].append({
            "tx_hash": tx_hash,
            "encrypted_data": encrypted_data,
            "status": "Pending",
            "aes_key": base64.b64encode(aes_key).decode(),
            "has_voted": False,
            "zth_amount": 1  # Add initial ZTH amount (1 ZTH)
        })
        print(f"Voter Data Added to Block: {selected_block.data}")  # Debug log

        # Save updated blockchain to file
        blockchain.save_to_file("./blockchain_files/blockchain.json")
        print(f"Blockchain Saved to File.")  # Debug log

        # Send voter details to user's email
        success = mailjet.send_email(
            recipient_email=email,
            subject="Your Voter Registration Details",
            recipient_name=name,
            nim=nim,
            dob=dob,
            tx_hash=tx_hash
        )

        if not success:
            flash("Failed to send email. Please try again.", "danger")

        flash("Voter registered successfully!", "success")
        return redirect(url_for('admin.admin_dashboard'))

    # Render registration form
    return render_template('admin/register.html')

@admin_bp.route('/validation', methods=['GET', 'POST'])
def validate_user():
    """Validate a user's registration."""
    global pending_voters

    # Load blockchain from file
    blockchain.load_from_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))

    if request.method == 'POST':
        # Get form data
        tx_hash = request.form['tx_hash']
        validator = request.form['validator']  # Get validator's name

        # Find the voter in the blockchain
        found = False
        for block in blockchain.chain:
            if "voters" in block.data:
                for voter in block.data["voters"]:
                    if voter["tx_hash"] == tx_hash and voter["status"] == "Pending":
                        # Update voter status and add validator
                        voter["status"] = "Validated"
                        voter["validator"] = validator
                        found = True
                        break
            if found:
                break

        if not found:
            return "Voter data not found."

        # Save updated blockchain to file
        blockchain.save_to_file(os.path.join(BLOCKCHAIN_DIR, "blockchain.json"))
        print(f"Voter data validated by {validator}")

        return redirect(url_for('admin.admin_dashboard'))

    # Load pending voters from blockchain
    pending_voters_list = []
    for block in blockchain.chain:
        if "voters" in block.data:
            for voter in block.data["voters"]:
                if voter["status"] == "Pending":
                    pending_voters_list.append({
                        "tx_hash": voter["tx_hash"],
                        "status": voter["status"],
                        "zth_amount": voter.get("zth_amount", 0)  # Include ZTH amount
                    })

    return render_template('admin/validation.html', voters=pending_voters_list)

temp_candidates = {}

@admin_bp.route('/candidate', methods=['GET', 'POST'])
def manage_candidate():
    """Manage candidate registration."""
    if request.method == 'POST':
        # Get form data
        candidate_number = request.form.get('candidate_number')
        candidate_name = request.form.get('candidate_name')
        candidate_photo = request.files.get('candidate_photo')  # Get the uploaded photo file

        # Validate input
        if not candidate_number or not candidate_name or not candidate_photo:
            flash("All fields are required.", "danger")
            return redirect(url_for('admin.manage_candidate'))

        # Check if the file is an image
        if not candidate_photo.content_type.startswith('image/'):
            flash("Only image files are allowed.", "danger")
            return redirect(url_for('admin.manage_candidate'))

        # Convert photo to Base64 string
        try:
            photo_base64 = base64.b64encode(candidate_photo.read()).decode()
        except Exception as e:
            flash(f"Failed to process photo: {e}", "danger")
            return redirect(url_for('admin.manage_candidate'))

        # Generate AES key for encryption
        aes_key = generate_aes_key()

        # Encrypt candidate data using AES
        encrypted_candidate_number = encrypt_data_aes(aes_key, candidate_number)
        encrypted_candidate_name = encrypt_data_aes(aes_key, candidate_name)

        # Hash the photo (optional, for reference)
        photo_hash = hashlib.sha256(photo_base64.encode()).hexdigest()

        # Generate TX Hash for the candidate
        tx_hash = generate_tx_hash({
            "candidate_number": candidate_number,
            "candidate_name": candidate_name,
            "photo_hash": photo_hash
        })

        # Generate a unique ID for the temporary candidate
        unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

        # Store large data in server-side storage
        temp_candidates[unique_id] = {
            "tx_hash": tx_hash,
            "aes_key": base64.b64encode(aes_key).decode(),  # Store AES key securely
            "encrypted_candidate_number": encrypted_candidate_number,
            "encrypted_candidate_name": encrypted_candidate_name,
            "photo_base64": photo_base64,  # Store original photo for reference
            "encrypted_photo_hash": encrypt_data_aes(aes_key, photo_hash)  # Add encrypted photo hash
        }

        # Save only the unique ID in session
        session['temp_candidate_id'] = unique_id

        # Redirect to /transaction
        return redirect(url_for('admin.transaction'))

    # Render candidate registration form
    return render_template('admin/add_candidate.html')

@admin_bp.route('/transaction', methods=['GET', 'POST'])
def transaction():
    if request.method == 'POST':
        temp_candidate_id = session.pop('temp_candidate_id', None)
        if not temp_candidate_id or temp_candidate_id not in temp_candidates:
            flash("No candidate data found. Please try again.", "danger")
            return redirect(url_for('admin.manage_candidate'))

        temp_candidate = temp_candidates.pop(temp_candidate_id)

        # Ensure all required keys exist in temp_candidate
        required_keys = ["tx_hash", "aes_key", "encrypted_candidate_number", "encrypted_candidate_name", "photo_base64", "encrypted_photo_hash"]
        if not all(key in temp_candidate for key in required_keys):
            flash("Incomplete candidate data. Please try again.", "danger")
            return redirect(url_for('admin.manage_candidate'))

        # Get admin details and balance
        admin_username = session.get('admin_username', 'Unknown')
        admin_tx_hash = None
        admin_balance = 0

        # Find the admin's TX Hash and current balance
        for block in blockchain.chain:
            if "admins" in block.data:
                for admin in block.data["admins"]:
                    try:
                        aes_key = base64.b64decode(admin["aes_key"])
                        encrypted_username = admin["encrypted_username"]
                        decrypted_username = decrypt_data_aes(
                            aes_key,
                            {
                                "iv": encrypted_username["iv"],
                                "ciphertext": encrypted_username["ciphertext"]
                            }
                        )
                        if decrypted_username == admin_username:
                            admin_tx_hash = admin["tx_hash"]
                            admin_balance = admin.get("zth_amount", 0)  # Use zth_amount from admin data
                            break
                    except Exception as e:
                        print(f"Error decrypting username: {e}")
                        continue

        gas_fee = 0.2012312414
        voting_fee = 0.40012323231
        total_fee = gas_fee + voting_fee

        # Check if admin has sufficient balance
        if admin_balance < total_fee:
            flash("Insufficient ZTH balance to register candidate. Required: {:.8f}, Available: {:.8f}".format(total_fee, admin_balance), "danger")
            return redirect(url_for('admin.manage_candidate'))

        # Deduct fees from admin balance
        admin_balance -= total_fee

        # Create system address and transaction
        system_address = f"0x{hashlib.sha256(b'System').hexdigest()[:8]}"
        tx_hash = generate_tx_hash({
            "from": admin_tx_hash,
            "to": system_address,
            "amount": -total_fee,
            "timestamp": time.time(),
            "gas_fee": gas_fee,
            "voting_fee": voting_fee
        })

        candidate_transaction = {
            "tx_hash": tx_hash,
            "from": admin_tx_hash,
            "to": system_address,
            "amount": -total_fee,
            "timestamp": time.time(),
            "gas_fee": gas_fee,
            "voting_fee": voting_fee
        }

        # Select a random block (excluding genesis block)
        available_blocks = [block for block in blockchain.chain if block.index > 0]
        if not available_blocks:
            flash("No available blocks for candidate registration. Please try again later.", "danger")
            return redirect(url_for('admin.admin_dashboard'))

        selected_block = random.choice(available_blocks)

        # Add candidate data to the selected block
        candidate_data = {
            "tx_hash": temp_candidate["tx_hash"],
            "aes_key": temp_candidate["aes_key"],  # Store AES key securely
            "encrypted_candidate_number": temp_candidate["encrypted_candidate_number"],
            "encrypted_candidate_name": temp_candidate["encrypted_candidate_name"],
            "encrypted_photo_hash": temp_candidate["encrypted_photo_hash"],  # Include encrypted photo hash
            "photo_base64": temp_candidate["photo_base64"]  # Store original photo for reference
        }

        if "candidates" not in selected_block.data:
            selected_block.data["candidates"] = []
        selected_block.data["candidates"].append(candidate_data)

        # Add transaction to the selected block
        if "transactions" not in selected_block.data:
            selected_block.data["transactions"] = []
        selected_block.data["transactions"].append(candidate_transaction)

        # Update the admin's zth_amount in all blocks
        for block in blockchain.chain:
            if "admins" in block.data:
                for admin in block.data["admins"]:
                    if admin["tx_hash"] == admin_tx_hash:
                        admin["zth_amount"] = admin_balance  # Update zth_amount
                        break

        # Save updated blockchain to file
        try:
            blockchain.save_to_file("./blockchain_files/blockchain.json")
            print(f"Candidate registered with TX Hash: {temp_candidate['tx_hash']} in block {selected_block.index}")
        except Exception as e:
            print(f"Failed to save blockchain: {e}")
            flash("Failed to save blockchain data. Please try again.", "danger")
            return redirect(url_for('admin.manage_candidate'))

        flash("Candidate registered successfully!", "success")
        return redirect(url_for('admin.candidate_view'))

    temp_candidate_id = session.get('temp_candidate_id', None)
    if not temp_candidate_id or temp_candidate_id not in temp_candidates:
        flash("No candidate data found. Please try again.", "danger")
        return redirect(url_for('admin.manage_candidate'))

    temp_candidate = temp_candidates[temp_candidate_id]

    gas_fee = 0.2012312414
    voting_fee = 0.40012323231
    total_fee = gas_fee + voting_fee

    return render_template(
        'admin/transaction-candidate.html',
        candidate=temp_candidate,
        gas_fee=gas_fee,
        voting_fee=voting_fee,
        total_fee=total_fee,
        admin_username=session.get('admin_username', 'Unknown')
    )
    
@admin_bp.route('/candidate_view', methods=['GET'])
def candidate_view():
    candidates = []

    # Collect all candidates from the blockchain
    for block in blockchain.chain:
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

    return render_template('admin/candidate_view.html', candidates=candidates)



@admin_bp.route('/block-maker', methods=['GET'])
def block_maker():
    """
    Display the current blockchain without allowing block creation.
    """
    # Check if the maximum number of blocks has been reached
    if len(blockchain.chain) >= blockchain.MAX_BLOCKS:
        flash("Maximum number of blocks reached. No more blocks can be added.", "info")

    # Convert blockchain to a list of dictionaries for the template
    blocks = [
        {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "data": block.data,
            "timestamp": block.timestamp,
            "nonce": block.nonce,
            "hash": block.hash,
            "validator": block.validator  # Include validator name
        }
        for block in blockchain.chain
    ]
    return render_template('admin/block_maker.html', blocks=blocks)

@admin_bp.route('/ledger', methods=['GET'])
def ledger():
    """Display all transactions in the blockchain."""
    transactions = []

    # Collect all transactions from the blockchain
    for block in blockchain.chain:
        if "transactions" in block.data:
            for transaction in block.data["transactions"]:
                try:
                    # Extract transaction data
                    tx_hash = transaction.get("tx_hash", "Unknown")
                    sender = transaction.get("from", "Unknown")
                    recipient = transaction.get("to", "Unknown")
                    amount = transaction.get("amount", 0)
                    timestamp = transaction.get("timestamp", 0)
                    gas_fee = transaction.get("gas_fee", 0)
                    voting_fee = transaction.get("voting_fee", 0)

                    # Convert timestamp to human-readable format
                    readable_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

                    # Append transaction data to list, including block index
                    transactions.append({
                        "tx_hash": tx_hash,
                        "sender": sender,
                        "recipient": recipient,
                        "amount": amount,
                        "timestamp": readable_timestamp,
                        "gas_fee": gas_fee,
                        "voting_fee": voting_fee,
                        "block_index": block.index  # Add block index
                    })
                except Exception as e:
                    print(f"Error processing transaction: {e}")
                    continue

    # Sort transactions by timestamp (optional)
    transactions.sort(key=lambda x: x["timestamp"], reverse=True)

    return render_template('admin/ledger.html', transactions=transactions)

@admin_bp.route('/voter-view')
def voter_view():
    """Display all validated voters without decrypting their data."""
    validated_voters = []

    # Collect all validated voters from the blockchain
    for block in blockchain.chain:
        if "voters" in block.data:
            for voter in block.data["voters"]:
                if voter.get("status") == "Validated":
                    # Extract encrypted data directly without decryption
                    encrypted_data = voter.get("encrypted_data", {})
                    validated_voters.append({
                        "tx_hash": voter.get("tx_hash"),
                        "voter_id": encrypted_data.get("voter_id", {}).get("ciphertext", "Encrypted"),
                        "nim": encrypted_data.get("nim", {}).get("ciphertext", "Encrypted"),
                        "name": encrypted_data.get("name", {}).get("ciphertext", "Encrypted"),
                        "dob": encrypted_data.get("dob", {}).get("ciphertext", "Encrypted"),
                        "email": encrypted_data.get("email", {}).get("ciphertext", "Encrypted"),
                        "timestamp": datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                        "block_index": block.index,
                        "has_voted": voter.get("has_voted", False),  # Include voting status
                        "zth_amount": voter.get("zth_amount", 0)  # Include ZTH amount
                    })

    return render_template('admin/voter_view.html', voters=validated_voters)

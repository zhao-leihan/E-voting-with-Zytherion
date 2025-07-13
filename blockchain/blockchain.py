import os
import json
import time
from blockchain.block import Block

class Blockchain:
    MAX_BLOCKS = 25  # Maximum number of blocks allowed

    def __init__(self, difficulty):
        """
        Initialize the blockchain.
        :param difficulty: Difficulty level for proof of work.
        """
        self.chain = []  # List to store blocks
        self.difficulty = difficulty  # Difficulty for mining (proof of work)
        # Load blockchain from file on initialization
        self.load_from_file()
        # If no chain exists, create a genesis block and save it
        if not self.chain:
            self.create_genesis_block()
            self.save_to_file("./blockchain_files/blockchain.json")

    def create_genesis_block(self):
        """
        Create the genesis block (first block in the blockchain).
        """
        genesis_block = Block(
            index=0,
            previous_hash="0",  # Previous hash is always "0" for genesis block
            data={"message": "Genesis Block", "validator": "Hexaforge"}
        )
        # Manually set the hash of the genesis block to "00000000"
        genesis_block.hash = "00000000"
        self.chain.append(genesis_block)
        print("Genesis block created with hash: 00000000")

    def add_block(self, new_block):
        """
        Add a new block to the blockchain.
        :param new_block: The new block to add.
        """
        # Check if the maximum number of blocks has been reached
        if len(self.chain) >= self.MAX_BLOCKS:
            print("Maximum number of blocks reached. Cannot add more blocks.")
            return False

        # Check for duplicate block index
        if any(block.index == new_block.index for block in self.chain):
            print(f"Block with index {new_block.index} already exists. Skipping addition.")
            return False

        # Set the previous hash of the new block to the hash of the last block
        new_block.previous_hash = self.chain[-1].hash
        # Add the new block to the chain
        self.chain.append(new_block)
        # Save the updated blockchain to file
        self.save_to_file("./blockchain_files/blockchain.json")
        print(f"New block added with hash: {new_block.hash}")
        return True

    def save_to_file(self, file_path):
        """
        Save the blockchain to a JSON file.
        :param file_path: Path to the JSON file.
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Ensure directory exists
            with open(file_path, 'w') as file:
                json.dump([block.to_dict() for block in self.chain], file, indent=4)
            print(f"Blockchain saved to {file_path} with {len(self.chain)} blocks.")
        except Exception as e:
            print(f"Failed to save blockchain to file: {e}")

    def load_from_file(self, file_path="./blockchain_files/blockchain.json"):
        """
        Load the blockchain from a JSON file.
        :param file_path: Path to the JSON file.
        """
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as file:
                    data = json.load(file)
                    # Validate uniqueness of block indices
                    indices = [block["index"] for block in data]
                    if len(indices) != len(set(indices)):
                        raise ValueError("Duplicate block indices found in blockchain file.")
                    self.chain = [Block.from_dict(block) for block in data]
                print(f"Blockchain loaded from {file_path} with {len(self.chain)} blocks.")
            except Exception as e:
                print(f"Failed to load blockchain from file: {e}")
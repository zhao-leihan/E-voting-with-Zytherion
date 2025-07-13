#block.py
import time
import hashlib
import json
import base64

class Block:
    def __init__(self, index, previous_hash, data, timestamp=None, nonce=0, validator="Hexaforge"):
        """
        Initialize a new block.
        :param index: Index of the block in the chain.
        :param previous_hash: Hash of the previous block.
        :param data: Data to be stored in the block.
        :param timestamp: Timestamp of block creation.
        :param nonce: Nonce for proof of work.
        :param validator: Name of the validator.
        """
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp or time.time()
        self.nonce = nonce
        self.hash = ""
        self.validator = validator  # Global validator name

    def calculate_hash(self):
        """
        Calculate the hash of the block including the validator.
        """
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "data": self.data,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "validator": self.validator  # Include validator in hash calculation
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty):
        """
        Mine the block by finding a hash that meets the difficulty criteria.
        """
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block mined: {self.hash}")

    def to_dict(self):
        """
        Convert block data to a dictionary, ensuring all data is JSON serializable.
        """
        # Ensure data is a dictionary
        if isinstance(self.data, str):  # If data is a string, try to parse it as JSON
            try:
                self.data = json.loads(self.data)  # Convert string back to dictionary
            except json.JSONDecodeError:
                self.data = {"error": "Invalid data format"}  # Handle invalid data gracefully

        # Ensure all values in data are serializable
        serializable_data = {}
        for key, value in self.data.items():
            if isinstance(value, bytes):  # Convert bytes to Base64 string
                serializable_data[key] = base64.b64encode(value).decode('utf-8')
            else:
                serializable_data[key] = value

        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "data": serializable_data,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "hash": self.hash,
            "validator": self.validator  # Include validator in serialized data
        }

    @staticmethod
    def from_dict(block_dict):
        """
        Create a Block object from a dictionary.
        """
        block = Block(
            index=block_dict["index"],
            previous_hash=block_dict["previous_hash"],
            data=block_dict["data"],
            timestamp=block_dict["timestamp"],
            nonce=block_dict["nonce"],
            validator=block_dict.get("validator", "Hexaforge")  # Default validator
        )
        block.hash = block_dict["hash"]
        return block
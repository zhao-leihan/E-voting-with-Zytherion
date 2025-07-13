import asyncio
import websockets
import json
import threading
from blockchain.blockchain import Block

class WebSocketServer:
    def __init__(self, blockchain, port):
        self.clients = set()
        self.blockchain = blockchain  # Blockchain instance
        self.port = port  # WebSocket port

    async def handler(self, websocket, path):
        """Handle WebSocket connections."""
        self.clients.add(websocket)
        try:
            async for message in websocket:
                await self.handle_message(message)
        finally:
            self.clients.remove(websocket)

    async def handle_message(self, message):
        """Handle incoming messages."""
        data = json.loads(message)
        if data["type"] == "new_block":
            new_block_data = data["block"]
            new_block = Block(
                new_block_data["index"],
                new_block_data["previous_hash"],
                new_block_data["data"],
                new_block_data["timestamp"],
                new_block_data["nonce"]
            )
            new_block.hash = new_block_data["hash"]

            if self.blockchain.is_valid_block(new_block):
                self.blockchain.chain.append(new_block)
                print("New block added to blockchain.")
                await self.broadcast(message)  # Broadcast the new block to all clients
            else:
                print("Invalid block received.")
    async def broadcast(self, message):
        """Broadcast a message to all connected clients."""
        if not self.clients:
            return
        await asyncio.wait([client.send(message) for client in self.clients])

    def start(self):
        """Start the WebSocket server."""
        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            start_server = websockets.serve(self.handler, "localhost", self.port)
            print(f"WebSocket server started on ws://localhost:{self.port}")
            loop.run_until_complete(start_server)
            loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
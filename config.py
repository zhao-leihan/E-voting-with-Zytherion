import os
class Config:
    MAILJET_API_KEY = os.getenv("MAILJET_API_KEY", "8c3a2f1aae70f4cea41a9a3af45be7a6")
    MAILJET_API_SECRET = os.getenv("MAILJET_API_SECRET", "52224ab0a74dddc44531403fb2eae091")
    BLOCKCHAIN_DIFFICULTY = 4
    P2P_PORT = 5000  # Default P2P port
    WEBSOCKET_PORT = 8765  # Default WebSocket port
    NODE_IP = "127.0.0.1"  # Default IP address (update this to your actual IP)
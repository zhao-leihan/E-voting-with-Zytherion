from flask import Flask
from admin import admin_bp
from user import user_bp
from blockchain.blockchain import Blockchain
from config import Config
import argparse
import os
from pyngrok import ngrok

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24).hex()

    # Register Blueprints
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')

    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run the blockchain application with specific ports and IP.")
    parser.add_argument('--port', type=int, default=5000, help="Port number for the node (default: 5000)")
    parser.add_argument('--ws-port', type=int, default=8765, help="WebSocket port for the node (default: 8765)")
    parser.add_argument('--ip', type=str, required=True, help="IP address of this node")
    args = parser.parse_args()

    # Initialize blockchain
    blockchain = Blockchain(difficulty=4)

    # Create app
    app = create_app()

 
    public_url = ngrok.connect(args.port)
    print(f" * ngrok tunnel URL: {public_url}")

    # Run Flask app
    app.run(host='0.0.0.0', port=args.port)
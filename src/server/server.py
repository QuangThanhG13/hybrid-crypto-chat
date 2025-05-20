from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
from dotenv import load_dotenv
from datetime import datetime
import logging
from flask_cors import CORS
from crypto_utils import HybridEncryption
from base64 import b64encode, b64decode

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage
users = {}  # username -> {public_key, private_key}
messages = []  # list of message objects
active_users = {}  # username -> socket_id

# Initialize encryption
crypto = HybridEncryption()

@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        logger.debug(f"Received registration request: {request.get_data()}")
        data = request.json
        if not data:
            logger.error("No JSON data received")
            return jsonify({'error': 'No data received'}), 400

        username = data.get('username')
        client_public_key = data.get('public_key')

        logger.debug(f"Registration attempt for username: {username}")

        if not username or not client_public_key:
            logger.error("Missing username or public key")
            return jsonify({'error': 'Missing username or public key'}), 400

        if username in users:
            logger.error(f"Username {username} already exists")
            return jsonify({'error': 'Username already exists'}), 400

        # Generate server's key pair for this user
        private_key, public_key = crypto.generate_rsa_keypair()

        # Store both keys
        users[username] = {
            'client_public_key': crypto.deserialize_public_key(client_public_key),
            'server_private_key': private_key,
            'server_public_key': public_key
        }

        # Return server's public key
        server_public_key_str = crypto.serialize_public_key(public_key)
        
        logger.info(f"Successfully registered user: {username}")
        return jsonify({
            'message': 'Registration successful',
            'server_public_key': server_public_key_str
        }), 201

    except Exception as e:
        logger.error(f"Error in register endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/users', methods=['GET', 'OPTIONS'])
def get_users():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        user_list = []
        for username, keys in users.items():
            user_list.append({
                'username': username,
                'public_key': crypto.serialize_public_key(keys['server_public_key'])
            })
        logger.debug(f"Retrieved {len(user_list)} users")
        return jsonify(user_list)
    except Exception as e:
        logger.error(f"Error in get_users endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    logger.info(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f'Client disconnected: {request.sid}')

@socketio.on('join')
def handle_join(data):
    try:
        username = data.get('username')
        if username:
            join_room(username)
            active_users[username] = request.sid
            emit('user_joined', {'username': username}, broadcast=True)
            logger.info(f"User {username} joined the chat")
    except Exception as e:
        logger.error(f"Error in handle_join: {e}")

@socketio.on('leave')
def handle_leave(data):
    try:
        username = data.get('username')
        if username:
            leave_room(username)
            if username in active_users:
                del active_users[username]
            emit('user_left', {'username': username}, broadcast=True)
            logger.info(f"User {username} left the chat")
    except Exception as e:
        logger.error(f"Error in handle_leave: {e}")

@socketio.on('message')
def handle_message(data):
    try:
        sender = data.get('sender')
        recipient = data.get('recipient')
        encrypted_payload = data.get('encrypted_payload')

        if not all([sender, recipient, encrypted_payload]):
            logger.error("Missing required message data")
            return

        # Get recipient's keys
        if recipient not in users:
            logger.error(f"Recipient {recipient} not found")
            return

        recipient_keys = users[recipient]
        
        # Decrypt message using sender's public key
        try:
            decrypted_message = crypto.decrypt(encrypted_payload, recipient_keys['server_private_key'])
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return

        # Store message
        message = {
            'sender': sender,
            'recipient': recipient,
            'encrypted_payload': encrypted_payload,
            'timestamp': datetime.utcnow()
        }
        messages.append(message)

        # Forward message to recipient if online
        if recipient in active_users:
            try:
                # Re-encrypt message for recipient
                recipient_encrypted = crypto.encrypt(decrypted_message, recipient_keys['client_public_key'])
                emit('message', {
                    'sender': sender,
                    'encrypted_payload': recipient_encrypted
                }, room=active_users[recipient])
                logger.info(f"Message forwarded from {sender} to {recipient}")
            except Exception as e:
                logger.error(f"Failed to re-encrypt message for recipient: {e}")
    except Exception as e:
        logger.error(f"Error in handle_message: {e}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))  # Use port 5001 by default
    logger.info(f"Starting server on port {port}...")
    socketio.run(app, debug=True, host='0.0.0.0', port=port) 
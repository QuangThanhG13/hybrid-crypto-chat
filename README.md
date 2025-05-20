# End-to-End Encrypted Chat System

A secure chat system implementing end-to-end encryption using hybrid cryptography (RSA + AES).

## Features

- End-to-end encryption using hybrid cryptography
- RSA for key exchange
- AES for message encryption
- Real-time messaging using WebSocket
- Server-side message routing
- Multiple client support

## Architecture

### Components

1. **Server**
   - Flask + SocketIO server
   - Handles user registration
   - Routes encrypted messages
   - Manages active users

2. **Clients**
   - Sender client for sending messages
   - Receiver client for receiving messages
   - Each client generates its own RSA key pair

3. **Encryption**
   - RSA (2048-bit) for key exchange
   - AES (256-bit) for message encryption
   - CBC mode with IV for AES

## Installation

1. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Unix/macOS
# or
.\venv\Scripts\activate  # On Windows
```

2. Install required packages:
```bash
pip install flask flask-socketio flask-cors python-dotenv cryptography
```

## Usage

1. Start the server:
```bash
cd src/server
python server.py
```
The server will run on port 5001 by default.

2. In a new terminal, start the receiver:
```bash
cd src/client
python receiver.py
```

3. In another terminal, start the sender:
```bash
cd src/client
python sender.py
```

## Message Flow

1. **Registration**
   - Each client generates RSA key pair
   - Clients register with server using their public key
   - Server stores public keys for message routing

2. **Sending Messages**
   - Sender generates random AES key
   - Message is encrypted with AES
   - AES key is encrypted with recipient's public key
   - Encrypted package is sent to server

3. **Message Routing**
   - Server receives encrypted message
   - Server forwards message to recipient
   - No decryption happens on server side

4. **Receiving Messages**
   - Recipient receives encrypted package
   - AES key is decrypted using private key
   - Message is decrypted using AES key

## Security Features

- RSA 2048-bit key pairs
- AES 256-bit encryption
- Unique IV for each message
- Perfect Forward Secrecy
- No message decryption on server

## Message Structure

```json
{
  "encrypted_data": "<AES encrypted message>",
  "encrypted_key": "<RSA encrypted AES key>",
  "iv": "<Initialization Vector>"
}
```

## Development

The project structure:
```
src/
├── client/
│   ├── base_client.py
│   ├── sender.py
│   └── receiver.py
└── server/
    ├── server.py
    └── crypto_utils.py
```

## Requirements

- Python 3.7+
- Flask
- Flask-SocketIO
- Flask-CORS
- python-dotenv
- cryptography

## License

MIT License 
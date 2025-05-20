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
1. End-to-End Encrypted Chat System Architecture
<img width="783" alt="ảnh" src="https://github.com/user-attachments/assets/d75429f4-0b14-43c1-b9c4-472abc730ebb" />

2. Work Flow End-to-End Encrypted System
<img width="638" alt="ảnh" src="https://github.com/user-attachments/assets/0923f6f3-f661-48c6-a493-786d9ace84e9" />

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
<img width="848" alt="ảnh" src="https://github.com/user-attachments/assets/8f4f108b-9806-4a9b-b4aa-c1dc3382a189" />
The server will run on port 5001 by default.

2. In a new terminal, start the receiver:
```bash
cd src/client
python receiver.py
```

<img width="560" alt="ảnh" src="https://github.com/user-attachments/assets/b82ec0e6-021d-4d02-b8f3-0932c2b58e1e" />

3. In another terminal, start the sender:
```bash
cd src/client
python sender.py
```
<img width="915" alt="ảnh" src="https://github.com/user-attachments/assets/904f7a49-c831-49aa-acc6-0e19559569b5" />

4. After decrypting in receiver.py: Decrypted message: "hello thanh"
<img width="288" alt="ảnh" src="https://github.com/user-attachments/assets/831d50f7-8ed1-4479-8579-db0d74169713" />

   
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

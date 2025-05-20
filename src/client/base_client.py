import socketio
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import b64encode, b64decode
import json
import requests

class BaseChatClient:
    def __init__(self, server_url="http://localhost:5001"):
        self.server_url = server_url
        self.sio = socketio.Client()
        self.username = None
        
        # Generate RSA key pair
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._public_key = self._private_key.public_key()
        
        # Setup event handlers
        self._setup_event_handlers()
    
    def _setup_event_handlers(self):
        @self.sio.event
        def connect():
            print('Connected successfully!')

        @self.sio.event
        def disconnect():
            print('Disconnected!')
            
    @property
    def public_key_str(self):
        """Returns public key as string (PEM format, base64 encoded)"""
        public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return b64encode(public_key_pem).decode('utf-8')
        
    def register(self, username):
        """Register user with server"""
        self.username = username
        register_data = {
            "username": username,
            "public_key": self.public_key_str
        }
        
        response = requests.post(
            f"{self.server_url}/register",
            json=register_data
        )
        return response.json()
        
    def connect_and_join(self):
        """Connect to server and join chat"""
        if not self.username:
            raise ValueError("Username must be registered before connecting")
            
        self.sio.connect(self.server_url)
        self.sio.emit('join', {'username': self.username})
        print(f"Joined chat with username: {self.username}")
        
    def disconnect(self):
        """Disconnect from server"""
        if self.sio.connected:
            self.sio.disconnect()
            
    def get_users(self):
        """Get list of users from server"""
        response = requests.get(f"{self.server_url}/users")
        return response.json() 
from base_client import BaseChatClient
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
import os
from base64 import b64encode, b64decode
import json
import time

class SenderClient(BaseChatClient):
    def __init__(self, server_url="http://localhost:5001"):
        super().__init__(server_url)
        
    def _encrypt_message(self, message, recipient_public_key):
        """Encrypt message using hybrid encryption"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Generate AES key and IV
        aes_key = os.urandom(32)  # AES-256
        iv = os.urandom(16)
        
        # Pad message
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        
        # Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA public key
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Create payload
        return {
            "encrypted_data": b64encode(encrypted_data).decode('utf-8'),
            "encrypted_key": b64encode(encrypted_key).decode('utf-8'),
            "iv": b64encode(iv).decode('utf-8')
        }
        
    def send_message(self, recipient_username, message):
        """Send message to recipient"""
        # Get user list and find recipient's public key
        users = self.get_users()
        recipient = next((user for user in users if user['username'] == recipient_username), None)
        
        if not recipient:
            raise ValueError(f"User not found: {recipient_username}")
            
        # Parse recipient public key
        recipient_key_pem = b64decode(recipient['public_key'])
        recipient_public_key = serialization.load_pem_public_key(recipient_key_pem)
        
        # Encrypt and send message
        encrypted_payload = self._encrypt_message(message, recipient_public_key)
        
        self.sio.emit('message', {
            'sender': self.username,
            'recipient': recipient_username,
            'encrypted_payload': encrypted_payload
        })
        
        print(f"Sent encrypted message to {recipient_username}")
        print("Encrypted payload:", json.dumps(encrypted_payload, indent=2))

def main():
    client = SenderClient()
    try:
        # Register with server
        client.register("sender_user")
        
        # Connect to server
        client.connect_and_join()
        
        while True:
            try:
                # Get message from user
                message = input("\nEnter message (or 'quit' to exit): ")
                
                if message.lower() == 'quit':
                    break
                    
                # Send message
                client.send_message("receiver_user", message)
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"\nError sending message: {e}")
                continue
        
        client.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")
        client.disconnect()

if __name__ == "__main__":
    main() 
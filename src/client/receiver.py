from base_client import BaseChatClient
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from base64 import b64decode
import time

class ReceiverClient(BaseChatClient):
    def __init__(self, server_url="http://localhost:5001"):
        super().__init__(server_url)
        self._setup_message_handler()
        
    def _setup_message_handler(self):
        @self.sio.on('message')
        def on_message(data):
            print(f"\nReceived message from {data['sender']}:")
            encrypted_payload = data['encrypted_payload']
            
            try:
                # Decrypt message
                decrypted_message = self._decrypt_message(encrypted_payload)
                print(f"Decrypted message: {decrypted_message}")
                
            except Exception as e:
                print(f"Error decrypting: {e}")
                
    def _decrypt_message(self, encrypted_payload):
        """Decrypt message using hybrid encryption"""
        # Decode and decrypt components
        encrypted_key = b64decode(encrypted_payload['encrypted_key'])
        encrypted_data = b64decode(encrypted_payload['encrypted_data'])
        iv = b64decode(encrypted_payload['iv'])
        
        # Decrypt AES key using RSA private key
        aes_key = self._private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad data
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data.decode('utf-8')
        
    def start_receiving(self):
        """Start receiving messages"""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nClosing connection...")
            self.disconnect()
            
def main():
    client = ReceiverClient()
    try:
        # Register with server
        client.register("receiver_user")
        
        # Connect and start receiving messages
        client.connect_and_join()
        client.start_receiving()
        
    except Exception as e:
        print(f"Error: {e}")
        client.disconnect()

if __name__ == "__main__":
    main() 
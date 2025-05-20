from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
import os
import time
import json
from base64 import b64encode, b64decode

class ECIESEncryption:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.SHARED_INFO_1 = b"/pa/generic/application"  # Pre-shared constant
        
    def generate_ephemeral_key(self):
        return ec.generate_private_key(self.curve)
        
    def derive_keys(self, shared_key, eph_pub_key, version="3.2"):
        # Use X9.63 KDF with SHA256
        version_bytes = version.encode('utf-8')
        info = version_bytes + self.SHARED_INFO_1 + eph_pub_key.public_bytes(
            encoding=ec.Encoding.X962,
            format=ec.PublicFormat.UncompressedPoint
        )
        
        kdf = X963KDF(
            algorithm=hashes.SHA256(),
            length=48,  # Generate 48 bytes for 3 keys (16 bytes each)
            sharedinfo=info
        )
        key_bytes = kdf.derive(shared_key)
        
        # Split into encryption, mac and iv keys
        enc_key = key_bytes[0:16]
        mac_key = key_bytes[16:32]
        iv_key = key_bytes[32:48]
        
        return enc_key, mac_key, iv_key

    def encrypt(self, plaintext, public_key):
        # Generate ephemeral key pair
        eph_private_key = self.generate_ephemeral_key()
        eph_public_key = eph_private_key.public_key()
        
        # Perform ECDH
        shared_key = eph_private_key.exchange(ec.ECDH(), public_key)
        
        # Generate nonce and timestamp
        nonce = os.urandom(16)
        timestamp = int(time.time() * 1000)
        
        # Derive keys
        enc_key, mac_key, iv_key = self.derive_keys(shared_key, eph_public_key)
        
        # Derive IV from nonce
        h = hmac.HMAC(iv_key, hashes.SHA256())
        h.update(nonce)
        iv = h.finalize()[:16]
        
        # Encrypt data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Calculate MAC
        shared_info_2 = self.get_shared_info_2(nonce, timestamp, eph_public_key, encrypted_data)
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(encrypted_data + shared_info_2)
        mac = h.finalize()
        
        # Prepare response
        response = {
            "encrypted_data": b64encode(encrypted_data).decode('utf-8'),
            "mac": b64encode(mac).decode('utf-8'),
            "nonce": b64encode(nonce).decode('utf-8'),
            "timestamp": timestamp,
            "ephemeral_public_key": b64encode(eph_public_key.public_bytes(
                encoding=ec.Encoding.X962,
                format=ec.PublicFormat.UncompressedPoint
            )).decode('utf-8')
        }
        
        return response

    def decrypt(self, encrypted_payload, private_key):
        # Extract payload components
        encrypted_data = b64decode(encrypted_payload["encrypted_data"])
        received_mac = b64decode(encrypted_payload["mac"])
        nonce = b64decode(encrypted_payload["nonce"])
        timestamp = encrypted_payload["timestamp"]
        eph_public_key_bytes = b64decode(encrypted_payload["ephemeral_public_key"])
        
        # Reconstruct ephemeral public key
        eph_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve,
            eph_public_key_bytes
        )
        
        # Perform ECDH
        shared_key = private_key.exchange(ec.ECDH(), eph_public_key)
        
        # Derive keys
        enc_key, mac_key, iv_key = self.derive_keys(shared_key, eph_public_key)
        
        # Verify MAC
        shared_info_2 = self.get_shared_info_2(nonce, timestamp, eph_public_key, encrypted_data)
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(encrypted_data + shared_info_2)
        calculated_mac = h.finalize()
        
        if not hmac.compare_digest(calculated_mac, received_mac):
            raise ValueError("Invalid MAC")
        
        # Derive IV from nonce
        h = hmac.HMAC(iv_key, hashes.SHA256())
        h.update(nonce)
        iv = h.finalize()[:16]
        
        # Decrypt data
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        
        return plaintext

    def get_shared_info_2(self, nonce, timestamp, eph_public_key, encrypted_data):
        # Base shared info
        shared_info_2_base = hashes.Hash(hashes.SHA256())
        shared_info_2_base.update(b"APPLICATION_SECRET")  # You should replace this with your actual application secret
        shared_info_2_base = shared_info_2_base.finalize()
        
        # Construct shared info 2
        timestamp_bytes = str(timestamp).encode('utf-8')
        eph_pub_bytes = eph_public_key.public_bytes(
            encoding=ec.Encoding.X962,
            format=ec.PublicFormat.UncompressedPoint
        )
        
        # Concatenate with sizes
        def concat_with_sizes(*args):
            result = b""
            for arg in args:
                result += len(arg).to_bytes(4, 'big') + arg
            return result
            
        return concat_with_sizes(
            shared_info_2_base,
            nonce,
            timestamp_bytes,
            eph_pub_bytes,
            b""  # Associated data (empty in this case)
        )

class HybridEncryption:
    def __init__(self):
        self.AES_KEY_SIZE = 32  # 256 bits
        self.AES_BLOCK_SIZE = 16  # 128 bits
        
    def generate_rsa_keypair(self):
        """Generate a new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key):
        """Serialize public key to string"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return b64encode(pem).decode('utf-8')

    def deserialize_public_key(self, key_str):
        """Deserialize public key from string"""
        key_bytes = b64decode(key_str)
        return serialization.load_pem_public_key(key_bytes)

    def generate_aes_key(self):
        """Generate a random AES key"""
        return os.urandom(self.AES_KEY_SIZE)

    def encrypt(self, plaintext, public_key):
        """
        Encrypt data using hybrid encryption:
        1. Generate random AES key
        2. Encrypt data with AES
        3. Encrypt AES key with RSA
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate random AES key and IV
        aes_key = self.generate_aes_key()
        iv = os.urandom(self.AES_BLOCK_SIZE)

        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Encrypt AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Prepare response
        response = {
            "encrypted_data": b64encode(encrypted_data).decode('utf-8'),
            "encrypted_key": b64encode(encrypted_key).decode('utf-8'),
            "iv": b64encode(iv).decode('utf-8')
        }
        
        return response

    def decrypt(self, encrypted_payload, private_key):
        """
        Decrypt data using hybrid encryption:
        1. Decrypt AES key with RSA private key
        2. Decrypt data with AES
        """
        # Extract components
        encrypted_data = b64decode(encrypted_payload["encrypted_data"])
        encrypted_key = b64decode(encrypted_payload["encrypted_key"])
        iv = b64decode(encrypted_payload["iv"])

        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()

        return plaintext 
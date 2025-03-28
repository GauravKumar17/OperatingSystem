import socket
import ssl
import os
import json
import hashlib
import hmac
import time
import threading
import logging
import uuid
from typing import Dict, Any, Callable, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecureIPC")

class SecurityManager:
    """Handles cryptographic operations and security features"""
    
    def __init__(self):
        self.session_keys: Dict[str, bytes] = {}
        self.nonces: Dict[str, int] = {}
        self.client_public_keys: Dict[str, rsa.RSAPublicKey] = {}
        
    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA key pair for asymmetric encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_public_key(self, public_key: rsa.RSAPublicKey) -> bytes:
        """Convert a public key to bytes for transmission"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_public_key(self, key_data: bytes) -> rsa.RSAPublicKey:
        """Convert bytes back to a public key"""
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
    
    def generate_session_key(self) -> bytes:
        """Generate a random session key for AES encryption"""
        return os.urandom(32)  # 256-bit key
    
    def encrypt_session_key(self, session_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt a session key using the recipient's public key"""
        return public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_session_key(self, encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt a session key using our private key"""
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def symmetric_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-GCM with the session key"""
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def symmetric_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-GCM with the session key"""
        iv = data[:12]
        tag = data[12:28]  # GCM tag is 16 bytes
        ciphertext = data[28:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def verify_nonce(self, client_id: str, nonce: int) -> bool:
        """Verify that the nonce is newer than the last one seen"""
        if client_id not in self.nonces:
            self.nonces[client_id] = nonce
            return True
        
        if nonce > self.nonces[client_id]:
            self.nonces[client_id] = nonce
            return True
        
        return False
    
    def generate_hmac(self, message: bytes, key: bytes) -> bytes:
        """Generate an HMAC for message authentication"""
        h = hmac.new(key, message, hashlib.sha256)
        return h.digest()
    
    def verify_hmac(self, message: bytes, signature: bytes, key: bytes) -> bool:
        """Verify an HMAC signature"""
        h = hmac.new(key, message, hashlib.sha256)
        computed_digest = h.digest()
        print(f"Expected HMAC: {computed_digest.hex()}")
        print(f"Received HMAC: {signature.hex()}")
        # The issue is here: hmac objects in Python don't have a verify method
        # Instead, we should directly compare the computed digest with the signature
        return hmac.compare_digest(computed_digest, signature)


class SecureMessage:
    """Represents a secure message format for IPC communication"""
    
    def __init__(self, 
                 sender_id: str, 
                 recipient_id: str, 
                 message_type: str, 
                 payload: Dict[str, Any],
                 nonce: Optional[int] = None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.message_type = message_type
        self.payload = payload
        self.nonce = nonce or int(time.time() * 1000)  # Millisecond timestamp as nonce
        self.message_id = str(uuid.uuid4())
    
    def to_bytes(self) -> bytes:
        """Convert message to bytes for transmission"""
        message_dict = {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "message_type": self.message_type,
            "payload": self.payload,
            "nonce": self.nonce,
            "message_id": self.message_id
        }
        return json.dumps(message_dict).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SecureMessage':
        """Create a message from received bytes"""
        message_dict = json.loads(data.decode())
        return cls(
            sender_id=message_dict["sender_id"],
            recipient_id=message_dict["recipient_id"],
            message_type=message_dict["message_type"],
            payload=message_dict["payload"],
            nonce=message_dict["nonce"]
        )


class SecureIPCServer:
    """Server component of the Secure IPC framework"""
    
    def __init__(self, 
                host: str = 'localhost', 
                port: int = 9000,
                certfile: Optional[str] = None,
                keyfile: Optional[str] = None):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.security = SecurityManager()
        self.private_key, self.public_key = self.security.generate_keypair()
        self.server_id = str(uuid.uuid4())
        self.running = False
        self.handlers: Dict[str, Callable] = {}
        self.clients: Dict[str, ssl.SSLSocket] = {}
        self.server_socket = None
        
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context for secure communication"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if self.certfile and self.keyfile:
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        else:
            # Generate self-signed cert for development/testing
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime
            
            name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
            ])
            
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(self.public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
                .sign(self.private_key, hashes.SHA256(), default_backend())
            )
            
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Create temporary files
            cert_path = f"temp_cert_{self.server_id}.pem"
            key_path = f"temp_key_{self.server_id}.pem"
            
            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            
            with open(key_path, "wb") as f:
                f.write(key_pem)
            
            self.certfile = cert_path
            self.keyfile = key_path
            
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        
        return context
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a function to handle a specific message type"""
        self.handlers[message_type] = handler
    
    def start(self):
        """Start the server and begin accepting connections"""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        ssl_context = self._create_ssl_context()
        self.server_socket = ssl_context.wrap_socket(
            self.server_socket,
            server_side=True
        )
        
        logger.info(f"Server started on {self.host}:{self.port}")
        
        # Start a thread to accept connections
        threading.Thread(target=self._accept_connections, daemon=True).start()
    
    def _accept_connections(self):
        """Accept incoming connections in a loop"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")
                threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True).start()
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket: ssl.SSLSocket):
        """Handle the connection with a client"""
        try:
            # Handshake: Send server's public key
            client_socket.sendall(self.security.serialize_public_key(self.public_key))
            
            # Receive client's public key
            client_public_key_data = client_socket.recv(4096)
            client_public_key = self.security.deserialize_public_key(client_public_key_data)
            
            # Receive client ID
            client_id_data = client_socket.recv(36)  # UUID is 36 chars
            client_id = client_id_data.decode()
            
            # Generate and send session key
            session_key = self.security.generate_session_key()
            encrypted_session_key = self.security.encrypt_session_key(session_key, client_public_key)
            client_socket.sendall(len(encrypted_session_key).to_bytes(4, byteorder='big'))
            client_socket.sendall(encrypted_session_key)
            
            # Store the client information
            self.security.client_public_keys[client_id] = client_public_key
            self.security.session_keys[client_id] = session_key
            self.clients[client_id] = client_socket
            
            logger.info(f"Client {client_id} connected")
            
            # Start receiving messages
            self._receive_messages(client_socket, client_id)
            
        except Exception as e:
            logger.error(f"Error in client handler: {e}")
            client_socket.close()
    
    def _receive_messages(self, client_socket: ssl.SSLSocket, client_id: str):
        """Receive and process messages from a client"""
        try:
            while self.running:
                # Receive message size
                size_data = client_socket.recv(4)
                if not size_data:
                    break
                
                message_size = int.from_bytes(size_data, byteorder='big')
                
                # Receive HMAC signature
                hmac_signature = client_socket.recv(32)  # SHA256 HMAC is 32 bytes
                
                # Receive encrypted message
                encrypted_data = b''
                while len(encrypted_data) < message_size:
                    chunk = client_socket.recv(min(4096, message_size - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                # Debug output
                print(f"Received encrypted message of size: {len(encrypted_data)} bytes")
                print(f"Received HMAC signature of size: {len(hmac_signature)} bytes")
                
                # Verify HMAC
                session_key = self.security.session_keys[client_id]
                if not self.security.verify_hmac(encrypted_data, hmac_signature, session_key):
                    logger.warning(f"HMAC verification failed for message from {client_id}")
                    print(f"Message size: {len(encrypted_data)}, HMAC size: {len(hmac_signature)}")
                    continue
                
                # Decrypt the message
                try:
                    decrypted_data = self.security.symmetric_decrypt(encrypted_data, session_key)
                    print(f"Successfully decrypted message: {decrypted_data[:100]}")
                except Exception as e:
                    logger.error(f"Decryption error: {e}")
                    continue
                
                # Parse the message
                try:
                    message = SecureMessage.from_bytes(decrypted_data)
                    print(f"Message parsed with type: {message.message_type}")
                except Exception as e:
                    logger.error(f"Message parsing error: {e}")
                    continue
                
                # Verify the nonce to prevent replay attacks
                if not self.security.verify_nonce(client_id, message.nonce):
                    logger.warning(f"Nonce verification failed for message from {client_id}")
                    continue
                
                # Handle the message
                if message.message_type in self.handlers:
                    print(f"Calling handler for message type: {message.message_type}")
                    response = self.handlers[message.message_type](message)
                    if response:
                        print(f"Sending response of type: {response.message_type}")
                        self.send_message(response)
                
        except Exception as e:
            logger.error(f"Error receiving messages from {client_id}: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
                del self.security.session_keys[client_id]
                del self.security.client_public_keys[client_id]
            client_socket.close()
            logger.info(f"Client {client_id} disconnected")
    
    def send_message(self, message: SecureMessage):
        """Send a secure message to a client"""
        if message.recipient_id not in self.clients:
            logger.warning(f"Recipient {message.recipient_id} not connected")
            return
        
        try:
            client_socket = self.clients[message.recipient_id]
            session_key = self.security.session_keys[message.recipient_id]
            
            # Convert message to bytes
            message_bytes = message.to_bytes()
            print(f"Sending message bytes: {message_bytes[:100]}")
            
            # Encrypt the message
            encrypted_data = self.security.symmetric_encrypt(message_bytes, session_key)
            
            # Generate HMAC
            hmac_signature = self.security.generate_hmac(encrypted_data, session_key)
            print(f"Generated HMAC: {hmac_signature.hex()}")
            
            # Send size, HMAC, and encrypted data
            client_socket.sendall(len(encrypted_data).to_bytes(4, byteorder='big'))
            client_socket.sendall(hmac_signature)
            client_socket.sendall(encrypted_data)
            print(f"Message sent to {message.recipient_id}")
            
        except Exception as e:
            logger.error(f"Error sending message to {message.recipient_id}: {e}")
    
    def broadcast_message(self, message_type: str, payload: Dict[str, Any]):
        """Send a message to all connected clients"""
        for client_id in list(self.clients.keys()):
            message = SecureMessage(
                sender_id=self.server_id,
                recipient_id=client_id,
                message_type=message_type,
                payload=payload
            )
            self.send_message(message)
    
    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        for client_socket in self.clients.values():
            client_socket.close()
        
        self.clients.clear()
        self.security.session_keys.clear()
        
        # Remove temporary certificate and key files
        if os.path.exists(self.certfile) and "temp_cert_" in self.certfile:
            os.remove(self.certfile)
        if os.path.exists(self.keyfile) and "temp_key_" in self.keyfile:
            os.remove(self.keyfile)
        
        logger.info("Server stopped")


class SecureIPCClient:
    """Client component of the Secure IPC framework"""
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 9000):
        self.server_host = server_host
        self.server_port = server_port
        self.security = SecurityManager()
        self.private_key, self.public_key = self.security.generate_keypair()
        self.client_id = str(uuid.uuid4())
        self.server_public_key = None
        self.session_key = None
        self.socket = None
        self.running = False
        self.handlers: Dict[str, Callable] = {}
        self.connected = False
    
    def register_handler(self, message_type: str, handler: Callable):
        """Register a function to handle a specific message type"""
        self.handlers[message_type] = handler
    
    def connect(self):
        """Connect to the server and perform the handshake"""
        try:
            # Create a socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap the socket with SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE  # In production, use proper cert verification
            
            self.socket = ssl_context.wrap_socket(
                self.socket,
                server_hostname=self.server_host
            )
            
            # Connect to the server
            self.socket.connect((self.server_host, self.server_port))
            
            # Handshake: Receive server's public key
            server_public_key_data = self.socket.recv(4096)
            self.server_public_key = self.security.deserialize_public_key(server_public_key_data)
            
            # Send client's public key
            self.socket.sendall(self.security.serialize_public_key(self.public_key))
            
            # Send client ID
            self.socket.sendall(self.client_id.encode())
            
            # Receive encrypted session key
            key_size = int.from_bytes(self.socket.recv(4), byteorder='big')
            encrypted_session_key = self.socket.recv(key_size)
            
            # Decrypt the session key
            self.session_key = self.security.decrypt_session_key(encrypted_session_key, self.private_key)
            print(f"Session key established: {self.session_key.hex()[:10]}...")
            
            self.running = True
            self.connected = True
            logger.info(f"Connected to server at {self.server_host}:{self.server_port}")
            
            # Start receiving messages
            threading.Thread(target=self._receive_messages, daemon=True).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def _receive_messages(self):
        """Receive and process messages from the server"""
        try:
            while self.running:
                # Receive message size
                size_data = self.socket.recv(4)
                if not size_data:
                    break
                
                message_size = int.from_bytes(size_data, byteorder='big')
                print(f"Receiving message of size: {message_size}")
                
                # Receive HMAC signature
                hmac_signature = self.socket.recv(32)  # SHA256 HMAC is 32 bytes
                print(f"Received HMAC: {hmac_signature.hex()}")
                
                # Receive encrypted message
                encrypted_data = b''
                while len(encrypted_data) < message_size:
                    chunk = self.socket.recv(min(4096, message_size - len(encrypted_data)))
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                print(f"Received full encrypted message of {len(encrypted_data)} bytes")
                
                # Verify HMAC
                if not self.security.verify_hmac(encrypted_data, hmac_signature, self.session_key):
                    logger.warning("HMAC verification failed for received message")
                    continue
                
                # Decrypt the message
                try:
                    decrypted_data = self.security.symmetric_decrypt(encrypted_data, self.session_key)
                    print(f"Successfully decrypted message: {decrypted_data[:100]}")
                except Exception as e:
                    logger.error(f"Decryption error: {e}")
                    continue
                
                # Parse the message
                try:
                    message = SecureMessage.from_bytes(decrypted_data)
                    print(f"Received message of type: {message.message_type}")
                except Exception as e:
                    logger.error(f"Message parsing error: {e}")
                    continue
                
                # Handle the message
                if message.message_type in self.handlers:
                    print(f"Handling message of type: {message.message_type}")
                    threading.Thread(
                        target=self.handlers[message.message_type],
                        args=(message,),
                        daemon=True
                    ).start()
                else:
                    print(f"No handler for message type: {message.message_type}")
                
        except Exception as e:
            if self.running:
                logger.error(f"Error receiving messages: {e}")
                self.disconnect()
    
    def send_message(self, message_type: str, payload: Dict[str, Any]) -> bool:
        """Send a secure message to the server"""
        if not self.connected:
            logger.warning("Not connected to server")
            return False
        
        try:
            # Create the message
            message = SecureMessage(
                sender_id=self.client_id,
                recipient_id="server", # the server ID will be properly resolved server-side
                message_type=message_type,
                payload=payload
            )
            
            # Convert message to bytes
            message_bytes = message.to_bytes()
            print(f"Sending message: {message_bytes[:100]}")
            
            # Encrypt the message
            encrypted_data = self.security.symmetric_encrypt(message_bytes, self.session_key)
            print(f"Encrypted message size: {len(encrypted_data)} bytes")
            
            # Generate HMAC
            hmac_signature = self.security.generate_hmac(encrypted_data, self.session_key)
            print(f"Generated HMAC: {hmac_signature.hex()}")
            
            # Send size, HMAC, and encrypted data
            self.socket.sendall(len(encrypted_data).to_bytes(4, byteorder='big'))
            self.socket.sendall(hmac_signature)
            self.socket.sendall(encrypted_data)
            print("Message sent successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        self.running = False
        self.connected = False
        if self.socket:
            self.socket.close()
        logger.info("Disconnected from server")


# Example usage code

def server_example():
    """Example of how to use the server"""
    
    server = SecureIPCServer(port=9000)
    
    # Define message handlers
    def handle_echo(message):
        print(f"Server received echo: {message.payload.get('text', '')}")
        
        # Create a response
        response = SecureMessage(
            sender_id=server.server_id,
            recipient_id=message.sender_id,
            message_type="echo_response",
            payload={"text": f"Echo: {message.payload.get('text', '')}"}
        )
        
        return response
    
    # Register handlers
    server.register_handler("echo", handle_echo)
    
    # Start the server
    server.start()
    
    try:
        # Keep the server running
        while True:
            cmd = input("Enter 'exit' to stop the server: ")
            if cmd.lower() == "exit":
                break
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


def client_example():
    """Example of how to use the client"""
    
    client = SecureIPCClient(server_port=9000)
    
    # Define message handlers
    def handle_echo_response(message):
        print(f"Client received: {message.payload.get('text', '')}")
    
    # Register handlers
    client.register_handler("echo_response", handle_echo_response)
    
    # Connect to the server
    if client.connect():
        try:
            # Send messages
            while True:
                text = input("Enter a message (or 'exit' to quit): ")
                if text.lower() == "exit":
                    break
                
                client.send_message("echo", {"text": text})
                
        except KeyboardInterrupt:
            pass
        finally:
            client.disconnect()
    else:
        print("Failed to connect to server")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        server_example()
    elif len(sys.argv) > 1 and sys.argv[1] == "client":
        client_example()
    else:
        print("Usage: python script.py [server|client]")
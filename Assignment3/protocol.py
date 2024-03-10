from cryptography.hazmat.primitives.asymmetric import dh
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization


class Protocol:
    # Initializer (Called from app.py)
    PROTOCOL_PREFIX = "AUTH_REQUEST"


    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._session_key = None
        self._shared_key = None
        self._shared_secret = None
        self._parameters = None
        self._private_key = None
        self._public_key = None
        self._peer_public_key = None

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self._parameters = dh.generate_parameters(generator=2, key_size=512) # 2048
        print("[*] Generated parameters")
        self._private_key = self._parameters.generate_private_key()
        self._public_key = self._private_key.public_key()
        print("[*] Generated keys")
        pem_public_key = self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        
        print(f"[+] Converted public key to PEM format:\n{pem_public_key}")
        pem_public_key = "PING" + b64encode(pem_public_key).decode()
        return pem_public_key
    
    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    # This function checks to see if a message is part of authentication protocl
    # If we find the encoded data that this is a protocol message
    def IsMessagePartOfProtocol(self, message):
        if b"PING" in message:
            print("[+] Protocol message detected")
            return True 
        elif b"PONG" in message:
            print("[+] Public key received from peer")
            peer_public_key = message.replace(b"PONG",b"")
            peer_public_key = b64decode(peer_public_key)
            peer_public_key = serialization.load_pem_public_key(peer_public_key, backend=default_backend())
            print("[*] Loaded peer public key")
    
            self._shared_key = self._private_key.exchange(peer_public_key)
            print("[*] Generated shared key")
            self._session_key = HKDF(algorithm=hashes.SHA256(), length=32, info=self._shared_secret.encode(), salt=None, backend=default_backend()).derive(self._shared_key)
            print(f"[+] Generated session key: {self._session_key}")
            return True

        else:
            print("[-] This isn't a protocol message")
            return False
 

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        try:
            peer_public_key = message.replace(b"PING",b"")
            peer_public_key = b64decode(peer_public_key)
            peer_public_key = serialization.load_pem_public_key(peer_public_key, backend=default_backend())
            print("[*] Loaded peer public key")
            self._parameters = peer_public_key.parameters()
            print("[*] Extracted parameters")
            self._private_key = self._parameters.generate_private_key()
            print("[*] Generated private key")
            
            self._shared_key = self._private_key.exchange(peer_public_key)
            print("[*] Generated shared key")
            self._session_key = HKDF(algorithm=hashes.SHA256(), length=32, info=self._shared_secret.encode(), salt=None, backend=default_backend()).derive(self._shared_key)
            print(f"[+] Generated session key: {self._session_key}")
        except Exception as e:
            print(f"[-] Error deriving key: {e}")
        

        try:
            self._public_key = self._private_key.public_key()
            pem_public_key = self._public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
            pem_public_key = "PONG" + b64encode(pem_public_key).decode()
            print(f"[+] Sending back my public key")
        except Exception as e:
            print(f"[-] Error obtaining public key: {e}") 
        
        return pem_public_key
        
    def SetSharedSecret(self, secret):
        self._shared_secret = secret
        print("[+] Set shared secret!")


    # Encrypting messages
    def EncryptAndProtectMessage(self, plain_text):
        print(f"Session key: {self._session_key}")
        if self._session_key != None and "PONG" not in plain_text:
            cipher = AES.new(self._session_key, AES.MODE_EAX)
            cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
            
            message = {
                "cipher_text" : b64encode(cipher_text).decode("utf-8"),
                "auth_tag" : b64encode(auth_tag).decode("utf-8"),
                "nonce" : b64encode(cipher.nonce).decode("utf-8"),
            }
            print(message)
            return json.dumps(message)
        else:
            return plain_text


    # Decrypting and verifying messages
    # TODO: ENSURE AN ERROR MESSAGE IS RETURNED IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        try: 
            message = json.loads(cipher_text)

            ct = b64decode(message["cipher_text"])
            tag = b64decode(message["auth_tag"])
            nonce = b64decode(message["nonce"])

            cipher = AES.new(self._session_key, AES.MODE_EAX, nonce=nonce)

            plain_text = cipher.decrypt_and_verify(ct, tag)
                
            return plain_text.decode("utf-8")
        except (ValueError, KeyError) as e:
            print(f"Decryption Error: {e}")
            #raise e
            return cipher_text


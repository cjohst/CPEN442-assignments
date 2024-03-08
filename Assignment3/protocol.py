from cryptography.hazmat.primitives.asymmetric import dh
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

class Protocol:
    # Initializer (Called from app.py)
    PROTOCOL_PREFIX = "AUTH_REQUEST"


    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._session_key = None
        self._shared_key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # Init message of the protocl with use DH,
    # This initilizes a A value and a P value for DH protocol
    # This returns just the plain text, we need to encrypt it with the shared KEY
    # This with make sure we are communication with the target server who also has the key
    # Throws exeption if shared key is not initialized in Protocol object
    # This gets the init message, the protocl returns a string
    # with the prefix followed by a : and 32 chars AUTH_REQUEST:DFLJSDLFKJSDLKFJLSDKJLGSDLFKJSLDJ
    # This identifies the request as wantint to establish secure connection to the server
    # **This creates the init message in a format that can be parsed by the server**
    def EncryptedInitMessage(self):
        if self._shared_key is None:
            raise Exception("No sharedKey Set")
        # TODO USE ENCYRPTION METHOD WHAT WE USE IN PROTOCOL WITH SHARED KEY
        # Replace with function like encrypt(message, self._shared_key)
        cipher_text = f"{Protocol.PROTOCOL_PREFIX}:48175900328479058203948576019284"
        if self.IsMessagePartOfProtocol(cipher_text) == False:
            raise Exception("Outgoing init message must pass protocol check")
        return cipher_text

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    # This function checks to see if a message is part of authentication protocl
    # If we find the encoded data that this is a protocol message
    def IsMessagePartOfProtocol(self, message):
        protocol_parts_len = 2
        parts = message.split(":")
        # looks like <prefix>:ljdfjj12l3kj1l2kj.. (len == 32)
        is_protocol = len(parts) == protocol_parts_len  \
                      and parts[0] == Protocol.PROTOCOL_PREFIX \
                      and len(parts[1]) == 32
        if is_protocol:
            return True
        return False
 

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSharedKey(self, key):
        self._shared_key = key
        pass

    # Encrypting messages
    def EncryptAndProtectMessage(self, plain_text):

        cipher = AES.new(self._key, AES.MODE_EAX)
        cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
        
        message = {
            "cipher_text" : b64encode(cipher_text).decode("utf-8"),
            "auth_tag" : b64encode(auth_tag).decode("utf-8"),
            "nonce" : b64encode(cipher.nonce).decode("utf-8"),
        }
        return json.dumps(message)


    # Decrypting and verifying messages
    # TODO: ENSURE AN ERROR MESSAGE IS RETURNED IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):

        try: 
            message = json.loads(cipher_text)

            ct = b64decode(message["cipher_text"])
            tag = b64decode(message["auth_tag"])
            nonce = b64decode(message["nonce"])

            cipher = AES.new(self._key, AES.MODE_EAX, nonce=nonce)

            plain_text = cipher.decrypt_and_verify(ct, tag)
                
            return plain_text.decode("utf-8")
        except (ValueError, KeyError) as e:
            print("Decryption Error")
            raise e


from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

class Protocol:
    # KEY TERMINOLIGY FOR UNDERSTANDIN THIS Protocol
    # PINGER -> participant that started a secure connection request
    # PONGER -> participant that responds to a secure connection request
    # SECURE CONNECTION -> perfect forward security through a DH session key
    #                      exchange
    # Prefixes that are both unique values that will mark a message as
    # part of an auth request
    # The ␟ (unicode U+241F) character is a character that a non protocol message is
    # very unlikely to contain as its not a character a user would usually type.
    # We use it to mark our protocol messages.
    #
    # Here one edge case breifly discussed and how they are handled.
    # Case: User includes "␟PONG␟" in a message. This will result in an Error. We must sanitize inputs to not include this.
    PONG_PREFIX = "␟PONG␟"
    PING_PREFIX = "␟PING␟"
    # Upon completion the PINGER recieving the PONG, PINGER will send a DONE message encryted with the session key
    DONE_PREFIX = "␟DONE␟"

    def __init__(self, init_shared_key):
        # _session_key: This is the SESSION KEY resulting from a DH exchange.
        # If this value is NONE then all messages will be encrypted / decrypted
        # using the init_shared_key which is assumed to shared already across
        # Client and Server
        # If this value is set then we will always encrypt messages with SESSION_KEY
        # Session key establishmetn can only happen once per instance.
        # _session_key is stored as bytes
        self._session_key = None
        # _init_shared_key: A key that is assumed to be on both client and Server
        # This is how messsages are sent by default if we do not have a unique session key
        # Established
        # This is stored as bytes
        self._init_shared_key = init_shared_key

        # These are paramaters set on the server and client when doing a DH key exchange
        self._parameters = None
        # We only store the pinger private key as long as it is needed to set up inital session key
        # We dont store the PONGER private key at all since its used only to create the session key once
        # then immediatly thrown away.
        self._pinger_private_key = None

        # Flag to let the PONGER know when they should start encyrpting using the session key instead of the
        # init_shared_key
        self.ping_pong_done = False

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # Returns an protocol init message that will request to the other party for a secure
    # Connection.
    # The return message will be an PREFIX + UNENCYRPTED public key. We assume that
    # This initialization message will be passed in a secure way (enrypted with some key in another step)
    def GetProtocolInitiationMessage(self):
        self._parameters = dh.generate_parameters(generator=2, key_size=512) # 2048
        # We must save this private key for recieiving a PONG from PONGER
        self._pinger_private_key = self._parameters.generate_private_key()
        pinger_public_key = self._pinger_private_key.public_key()
        pem_public_key = pinger_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

        pem_public_key = Protocol.PING_PREFIX + b64encode(pem_public_key).decode()
        return pem_public_key

    # Checking if a received message is part of your protocol (called from app.py)
    # This function checks to see if a message is part of authentication protocl
    # Protocol messages are contain a ␟PING␟  wrapped in the unicode character “␟” (U+241F)
    # The message is a utf-8 string!
    # We did this since this is a character that wont be accidently sent in a message.
    # So no messages would be accidently included in the protocol
    def IsMessagePartOfProtocol(self, message):
        if Protocol.PING_PREFIX in message:
            return True
        elif Protocol.PONG_PREFIX in message:
            return True
        elif Protocol.DONE_PREFIX in message:
            return True
        else:
            return False


    # Processing protocol message
    # @ message - utf-8 string
    # The message must be plain text and not cipher text
    # Messages passed in are assumed to pass an IsPrototolcMessageCheck function.
    # Assuming a vaild message is passed in post function call the prtcl object
    # will encrypte / decrypt all messages with the SESSION_KEY rather than the
    # INIT_SHARED_KEY
    # IF Protocol Message is a PING we will return a PONG message
    # if Protocol message is a PONG we will return None
    # If Message is not part of protocl all bets we will return None
    # @ return value is a utf-8 string
    def ProcessReceivedProtocolMessage(self, message):
        message_bytes = message.encode('UTF-8')
        # PING reciever needs to set paramaaters from public key
        if Protocol.PING_PREFIX.encode('UTF-8') in message_bytes:
            pong_msg = self._recievePing(message_bytes)
            return pong_msg
        if Protocol.PONG_PREFIX.encode('UTF-8') in message_bytes:
            done_msg = self._recievePong(message_bytes)
            return done_msg
        if Protocol.DONE_PREFIX.encode('UTF-8') in message_bytes:
            self.ping_pong_done = True

    def _recievePing(self, message):
        decoded_pub_key = b64decode(message.replace(Protocol.PING_PREFIX.encode('UTF-8'),b""))
        pinger_public_key = serialization.load_pem_public_key(decoded_pub_key, backend=default_backend())
        self._parameters = pinger_public_key.parameters()
        private_key = self._parameters.generate_private_key()
        self._session_key = self._prepKeyForAES(private_key.exchange(pinger_public_key))

        # PONGER must send back his public key so PINGER can also make the session key
        ponger_public_key = private_key.public_key()
        pem_public_key = ponger_public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        pem_public_key = Protocol.PONG_PREFIX + b64encode(pem_public_key).decode()
        return pem_public_key


    def _recievePong(self, message):
        # ponger is the person who sent the PONG
        decoded_pub_key = b64decode(message.replace(Protocol.PONG_PREFIX.encode('UTF-8'),b""))
        ponger_public_key = serialization.load_pem_public_key(decoded_pub_key, backend=default_backend())
        if self._pinger_private_key is None:
            raise Exception("The private key is NONE and was likely not established or saved by the PINGER")
        self._session_key = self._prepKeyForAES(self._pinger_private_key.exchange(ponger_public_key))
        # Cleaning up private key as we no longer need it
        # Note that this just prevents accidental leakage of private key from
        # calling the API. _private_key will still be in memmory although unreferenced
        del self._pinger_private_key
        # PINGER also needs to mark the handshake done on their end
        self.ping_pong_done = True
        return Protocol.DONE_PREFIX


    def SetSharedKey(self, secret):
        self._init_shared_key = self._prepKeyForAES(secret.encode('utf-8'))


    # Encrypting messages
    # @plain_text is a utf-8 string
    # This encryptes ALL messages between server and client.
    # IF session_key is established messages will be encrypted with that ket.
    # IF session_key is NONE then we will encrypt messages with the init_shared_key that
    # both client and server have shared already.
    # IF NO KEY IS ESTABLISHD: this function will not encrypt any messages and return UNENCYRPTED messages.
    # RETURNS A PYTHON utf-8 string
    def EncryptAndProtectMessage(self, plain_text):
        if self.ping_pong_done and self._session_key != None:
            return self._encrypt(plain_text, self._session_key)
        elif self._init_shared_key != None:
            return self._encrypt(plain_text, self._init_shared_key)
        else:
            return plain_text

    def _encrypt(self, plain_text, key):
        try:
            cipher = AES.new(key, AES.MODE_EAX)
            cipher_text, auth_tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))

            message = {
                "cipher_text" : b64encode(cipher_text).decode("utf-8"),
                "auth_tag" : b64encode(auth_tag).decode("utf-8"),
                "nonce" : b64encode(cipher.nonce).decode("utf-8"),
            }
            return json.dumps(message)
        except Exception as e:
            print(f"Encryption error, Bad key?? {e}")
            return e

    # Decrypting and verifying messages
    # @cipher_text is a utf-8 string
    # This decrypts ALL messages between server and client.
    # IF session_key is established messages will be decrypted with that key.
    # IF session_key is NONE then we will encrypt/decrypt messages with the init_shared_key
    # IF NO KEY IS ESTABLISHD: this function will not decrypt any messages.
    # RETURNS A PYTHON utf-8 string
    def DecryptAndVerifyMessage(self, cipher_text):
        if self._session_key != None:
            return self._decrypt(cipher_text, self._session_key)
        elif self._init_shared_key != None:
            return self._decrypt(cipher_text, self._init_shared_key)
        return cipher_text

    def _decrypt(self, cipher_text, key):
        try:
            message = json.loads(cipher_text)
            ct = b64decode(message["cipher_text"])
            tag = b64decode(message["auth_tag"])
            nonce = b64decode(message["nonce"])
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plain_text = cipher.decrypt_and_verify(ct, tag)
            return plain_text.decode("utf-8")
        except Exception as e:
            # must be caught by user
            raise e

    # Key must be in bytes data type.
    # AES keys for our usecase use a key size of 32 bytes
    # returns a key of a size num_bytes
    def _prepKeyForAES(self, key):
         # Create an HKDF instance with the desired parameters
         hkdf = HKDF(
             algorithm=hashes.SHA256(),
             length=32,
             salt=None,
             info=None,
             backend=default_backend()
         )
         # Create a hash object
         derived_key = hkdf.derive(key)
         return derived_key

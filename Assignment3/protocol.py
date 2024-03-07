from cryptography.hazmat.primitives.asymmetric import dh

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
        self._session_key = key
        pass

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSharedKey(self, key):
        self._shared_key = key
        pass

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        # Add check here to NOT encrytp the message if the session key is not established yet
        # What we can do is use the shared key to start
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text

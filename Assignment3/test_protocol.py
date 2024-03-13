from protocol import Protocol
import pytest

"""
 TO test

 1. Init protocol message
 2. Is part of protocol
 3. Handling PING - data type of string, return type of string
 4. Handling PONG - data type of string, return type of string

 5. Encrypt/Decrypt with no key - string / string 2 1
 6. Encrypt/Decrypt with init shared key
 7. Encrype/Decrypt with a session key
"""

def test_e2eTesting():
    e2e_test_key = "testkey123"
    # Testing Init message functionality
    pinger = Protocol()
    pinger.SetSharedKey(e2e_test_key)
    init_msg = pinger.GetProtocolInitiationMessage()
    print("Returned from init msg: " + init_msg)
    assert type(init_msg) == str
    assert Protocol.PING_PREFIX in init_msg

    # Test to see "Is Part of Protocol"
    # TESTING FOR PING message
    assert pinger.IsMessagePartOfProtocol(init_msg) == True

    # Common edge case testing messong containgin ping and post. it should not pass protocol checking"
    randomMsg = "This is a random PING message and POST"
    assert pinger.IsMessagePartOfProtocol(randomMsg) == False

    # Testing handling PING message
    ping_msg = init_msg

    ponger = Protocol()
    ponger.SetSharedKey(e2e_test_key)
    pong_msg = ponger.ProcessReceivedProtocolMessage(ping_msg)
    print("Pong pub key in pytest: " + pong_msg)
    print(f"ponger session_key: f{ponger._session_key}")
    # test PONG message is part of protocol
    # And test correct return types
    assert type(pong_msg) == str
    assert Protocol.PONG_PREFIX in pong_msg
    assert pinger.IsMessagePartOfProtocol(pong_msg) == True

    # Testing handling of PONG message
    done_msg = pinger.ProcessReceivedProtocolMessage(pong_msg)

    assert done_msg == Protocol.DONE_PREFIX
    print(f"pinger session_key: {pinger._session_key}")

    # assert both pinger and ponger have same key
    assert ponger._session_key == pinger._session_key

    # Test PONGER handles done message
    ponger.ProcessReceivedProtocolMessage(done_msg)
    assert ponger.ping_pong_done == True

    # Now try encrypting / Decrypt with session keys established
    # first case is normal case no attempt to modify integrity
    plain_text_pinger = "Hi my name is Jarvis your best friend."
    cipher_text_pinger = pinger.EncryptAndProtectMessage(plain_text_pinger)

    # no modifications
    cipher_text_ponger = cipher_text_pinger
    plain_text_ponger = ponger.DecryptAndVerifyMessage(cipher_text_ponger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert type(plain_text_pinger) == str
    assert plain_text_pinger == plain_text_ponger

    # Now test again but send from ponger to pinger
    plain_text_ponger = "Jarvis u are such a terrible person"
    cipher_text_ponger = ponger.EncryptAndProtectMessage(plain_text_ponger)

    # no modifications
    cipher_text_pinger = cipher_text_ponger
    plain_text_pinger = ponger.DecryptAndVerifyMessage(cipher_text_pinger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert plain_text_pinger == plain_text_ponger
    assert type(cipher_text_ponger) == str


    # NOW test integrity by modifying the message in transit
    plain_text_ponger = "Jarvis u are such a terrible person"
    cipher_text_ponger = ponger.EncryptAndProtectMessage(plain_text_ponger)

    # ADD some bites to show tampering
    cipher_text_pinger = cipher_text_ponger + "Assdding noise"
    with pytest.raises(Exception):
        plain_text_pinger = ponger.DecryptAndVerifyMessage(cipher_text_pinger)

# Testing the protocol when there is NO session key
def test_noSessionKey():
    pinger = Protocol()
    ponger = Protocol()

    pinger.SetSharedKey("TestKey123")
    ponger.SetSharedKey("TestKey123")

    # Now try encrypting / Decrypt with session keys established
    # first case is normal case no attempt to modify integrity
    plain_text_pinger = "Hi my name is Jarvis your best friend."
    cipher_text_pinger = pinger.EncryptAndProtectMessage(plain_text_pinger)

    # no modifications
    cipher_text_ponger = cipher_text_pinger
    plain_text_ponger = ponger.DecryptAndVerifyMessage(cipher_text_ponger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert plain_text_pinger == plain_text_ponger

    # Now test again but send from ponger to pinger
    plain_text_ponger = "Jarvis u are such a terrible person"
    cipher_text_ponger = ponger.EncryptAndProtectMessage(plain_text_ponger)

    # no modifications
    cipher_text_pinger = cipher_text_ponger
    plain_text_pinger = ponger.DecryptAndVerifyMessage(cipher_text_pinger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert plain_text_pinger == plain_text_ponger


    # NOW test integrity by modifying the message in transit
    plain_text_ponger = "Jarvis u are such a terrible person"
    cipher_text_ponger = ponger.EncryptAndProtectMessage(plain_text_ponger)

    # ADD some bites to show tampering
    cipher_text_pinger = cipher_text_ponger + "Assdding noise"
    # expected to FAIL since we have modified message in transit
    with pytest.raises(Exception):
        plain_text_pinger = ponger.DecryptAndVerifyMessage(cipher_text_pinger)

def test_NoKey():
    pinger = Protocol()
    ponger = Protocol()
    pinger.SetSharedKey("testKey")
    ponger.SetSharedKey("testKey")

    # Now try encrypting / Decrypt with session keys established
    # first case is normal case no attempt to modify integrity
    plain_text_pinger = "Hi my name is Jarvis your best friend."
    cipher_text_pinger = pinger.EncryptAndProtectMessage(plain_text_pinger)

    # no modifications
    cipher_text_ponger = cipher_text_pinger
    plain_text_ponger = ponger.DecryptAndVerifyMessage(cipher_text_ponger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert plain_text_pinger == plain_text_ponger

    # Now test again but send from ponger to pinger
    plain_text_ponger = "Jarvis u are such a terrible person"
    cipher_text_ponger = ponger.EncryptAndProtectMessage(plain_text_ponger)

    # no modifications
    cipher_text_pinger = cipher_text_ponger
    plain_text_pinger = ponger.DecryptAndVerifyMessage(cipher_text_pinger)
    print("ponger plaing text " + plain_text_ponger)
    print("plain text pinger " + plain_text_pinger)
    assert plain_text_pinger == plain_text_ponger

# A test to reproduce a bug where the session key is only available for one side.
# In this buf the session key exists for the PONGER but not PINGER so when PONGER
# Sends a message and encrypts it with the session key before the PINGER has the key.
# The solution to this bug was to add an extra set sending a DONE message
# from PINGER to PONGER after PINGER receives a PONG
def test_OneSideWithSessionKeyOnly():
    pinger = Protocol()
    ponger = Protocol()
    pinger.SetSharedKey("testKey")
    ponger.SetSharedKey("testKey")

    init_msg = pinger.GetProtocolInitiationMessage()
    pong_msg = ponger.ProcessReceivedProtocolMessage(init_msg)

    cipher_text = ponger.EncryptAndProtectMessage(pong_msg)
    pong_msg_received = pinger.DecryptAndVerifyMessage(cipher_text)

    pinger.ProcessReceivedProtocolMessage(pong_msg_received)

    ## For test to pass both must have the same session key
    assert ponger._session_key == pinger._session_key

def testDifferentKeys():
    pinger = Protocol()
    ponger = Protocol()
    pinger.SetSharedKey("testKey")
    ponger.SetSharedKey("keyTest")

    # Now try encrypting / Decrypt with session keys established
    plain_text_pinger = "Hi my name is Jarvis your best friend."
    cipher_text_pinger = pinger.EncryptAndProtectMessage(plain_text_pinger)

    # Check if we can decrypt message with different initial secret
    with pytest.raises(Exception):
        cipher_text_ponger = cipher_text_pinger
        _ = ponger.DecryptAndVerifyMessage(cipher_text_ponger)


def testSendInPlainTextWithoutKey():
    pinger = Protocol()
    ponger = Protocol()

    # Now try encrypting / Decrypt with session keys established
    plain_text_pinger = "Hi my name is Jarvis your best friend."
    cipher_text_pinger = pinger.EncryptAndProtectMessage(plain_text_pinger)

    # Check if we can decrypt message with different initial secret
    cipher_text_ponger = cipher_text_pinger
    should_be_plain_text = ponger.DecryptAndVerifyMessage(cipher_text_ponger)

    assert should_be_plain_text == plain_text_pinger

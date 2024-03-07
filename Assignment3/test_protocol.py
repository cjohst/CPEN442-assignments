import protocol
import pytest

def test_EncryptedInitMessage():
    prtcl = protocol.Protocol()
    # test assertion with no key assigned
    with pytest.raises(Exception):
        init_msg = prtcl.EncryptedInitMessage()

    # test returns init message if key is assigned
    prtcl.SetSharedKey("testkey1")
    init_msg = prtcl.EncryptedInitMessage()
    print(init_msg)
    assert isinstance(init_msg, str)
    # end testing here since exact protocol not defined


## depends on above test making sure the message returned from it passes
def test_IsMessagePartOfProtocol():
    prtcl = protocol.Protocol()
    prtcl.SetSharedKey("testkey1")
    notProtocolMsg = "testMessage"
    ## this is coupled to the implimentation of EncyrptedInitMessage test
    goodProtocolMsg = prtcl.EncryptedInitMessage()
    assert prtcl.IsMessagePartOfProtocol(notProtocolMsg) == False
    assert prtcl.IsMessagePartOfProtocol(goodProtocolMsg) == True
    ## small changes to procol should read false too
    notgoodProtocolMsg = prtcl.EncryptedInitMessage() + "1"
    assert prtcl.IsMessagePartOfProtocol(notgoodProtocolMsg) == False
    notgoodProtocolMsg2 = "2" +prtcl.EncryptedInitMessage()
    assert prtcl.IsMessagePartOfProtocol(notgoodProtocolMsg2) == False

package org.dcache.xrootd.protocol.messages;
import org.dcache.xrootd.protocol.XrootdProtocol;

public class LoginResponse extends AbstractResponseMessage
{
    public LoginResponse(int sId, byte [] ssId, String sec) {
        super(sId, XrootdProtocol.kXR_ok, sec.length()+16);

        //		.. put sessionId and security info
        put(ssId);
        putCharSequence(sec);
    }
}

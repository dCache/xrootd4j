package org.dcache.xrootd.core;

import java.security.SecureRandom;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;

public class XrootdSessionIdentifier
{
    private static final SecureRandom _random = new SecureRandom();

    private final byte[] _sessionId;

    public XrootdSessionIdentifier()
    {
        _sessionId = new byte[SESSION_ID_SIZE];
        _random.nextBytes(_sessionId);
    }

    public XrootdSessionIdentifier(byte[] sessionId)
    {
        checkArgument(sessionId.length == SESSION_ID_SIZE);
        _sessionId = sessionId;
    }

    public byte[] getBytes()
    {
        return Arrays.copyOf(_sessionId, _sessionId.length);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        XrootdSessionIdentifier that = (XrootdSessionIdentifier) o;
        return Arrays.equals(_sessionId, that._sessionId);
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(_sessionId);
    }
}

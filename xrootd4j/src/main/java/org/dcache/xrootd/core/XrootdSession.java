package org.dcache.xrootd.core;

import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.jboss.netty.channel.Channel;

import javax.security.auth.Subject;

public class XrootdSession
{
    private final Channel _channel;
    private final XrootdSessionIdentifier _id;
    private final LoginRequest _loginRequest;
    private Subject _subject;

    public XrootdSession(XrootdSessionIdentifier id, Channel channel, LoginRequest loginRequest)
    {
        _id = id;
        _channel = channel;
        _loginRequest = loginRequest;
    }

    public boolean hasOwner(Subject subject)
    {
        if (_subject == null) {
            return subject == null;
        } else {
            return _subject.getPrincipals().equals(subject.getPrincipals());
        }
    }

    public void setSubject(Subject subject)
    {
        _subject = subject;
    }

    public Subject getSubject()
    {
        return _subject;
    }

    public Channel getChannel()
    {
        return _channel;
    }

    public XrootdSessionIdentifier getSessionIdentifier()
    {
        return _id;
    }

    public String getToken()
    {
        return _loginRequest.getToken();
    }

    public String getUserName()
    {
        return _loginRequest.getUserName();
    }

    public int getClientProtocolVersion()
    {
        return _loginRequest.getClientProtocolVersion();
    }

    public boolean isAdmin()
    {
        return _loginRequest.isAdmin();
    }

    public int getPID()
    {
        return _loginRequest.getPID();
    }

    public boolean supportsAsyn()
    {
        return _loginRequest.supportsAsyn();
    }
}

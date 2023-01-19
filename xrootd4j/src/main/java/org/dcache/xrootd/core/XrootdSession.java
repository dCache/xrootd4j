/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.core;

import io.netty.channel.Channel;

import javax.security.auth.Subject;

import java.io.Serializable;

import org.dcache.xrootd.protocol.messages.LoginRequest;

public class XrootdSession
{
    private final Channel                 _channel;
    private final XrootdSessionIdentifier _id;
    private final LoginRequest            _loginRequest;
    private Subject                       _subject;
    private Serializable                  _delegatedCredential;

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

    /*
     *  If there is a delegated proxy, it is set on the session
     *  so it can be accessed by subsequent open requests.
     */
    public void setDelegatedCredential(Serializable delegatedCredential)
    {
        _delegatedCredential = delegatedCredential;
    }

    public void setSubject(Subject subject)
    {
        _subject = subject;
    }

    public Serializable getDelegatedCredential()
    {
        return _delegatedCredential;
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

/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.core;

import com.google.common.io.BaseEncoding;

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

    @Override
    public String toString()
    {
        return BaseEncoding.base16().encode(_sessionId);
    }
}

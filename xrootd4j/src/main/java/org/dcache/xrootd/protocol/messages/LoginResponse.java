/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.core.XrootdSessionIdentifier;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;

public class LoginResponse extends AbstractXrootdResponse
{
    private final XrootdSessionIdentifier sessionId;
    private final String sec;

    public LoginResponse(XrootdRequest request, XrootdSessionIdentifier sessionId, String sec)
    {
        super(request, kXR_ok);

        this.sessionId = sessionId;
        this.sec = sec;
    }

    public XrootdSessionIdentifier getSessionId()
    {
        return sessionId;
    }

    public String getSec()
    {
        return sec;
    }

    @Override
    protected int getLength()
    {
        return super.getLength() + SESSION_ID_SIZE + (sec.isEmpty() ? 0 : sec.length() + 1);
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);
        buffer.writeBytes(sessionId.getBytes());
        if (!sec.isEmpty()) {
            buffer.writeBytes(sec.getBytes(US_ASCII));
            buffer.writeByte('\0');
        }
    }

    @Override
    public String toString()
    {
        return "login-response[" + sessionId + "," + sec + "]";
    }
}

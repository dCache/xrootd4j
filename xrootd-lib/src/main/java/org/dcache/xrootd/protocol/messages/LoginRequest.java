/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class LoginRequest extends AbstractRequestMessage
{
    private final String username;
    private final short role;
    private final short capver;
    private final int pid;
    private final String token;

    public LoginRequest(ChannelBuffer buffer)
    {
        super(buffer);

        if (getRequestID() != XrootdProtocol.kXR_login)
            throw new IllegalArgumentException("doesn't seem to be a kXR_login message");

        int pos =
            buffer.indexOf(8, 16, (byte)0); // User name is padded with '\0'
        if (pos > -1) {
            username = buffer.toString(8,
                                       pos - 8,
                                       XROOTD_CHARSET);
        } else {
            username = buffer.toString(8,
                                       8,
                                       XROOTD_CHARSET);
        }

        pid = buffer.getInt(4);
        capver = buffer.getUnsignedByte(18);
        role = buffer.getUnsignedByte(19);

        int tlen = buffer.getInt(20);
        token = buffer.toString(24, tlen, XROOTD_CHARSET);
    }

    public String getUserName()
    {
        return username;
    }

    public boolean supportsAsyn()
    {
        return (capver & 0x80) == 0x80 ? true : false;
    }

    public int getClientProtocolVersion()
    {
        return capver & 0x3f;
    }

    public boolean isAdmin()
    {
        return role == XrootdProtocol.kXR_useradmin ? true : false;
    }

    public int getPID()
    {
        return pid;
    }

    public String getToken()
    {
        return token;
    }

}

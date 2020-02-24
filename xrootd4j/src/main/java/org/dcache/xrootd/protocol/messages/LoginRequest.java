/**
 * Copyright (C) 2011-2020 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_useradmin;

public class LoginRequest extends AbstractXrootdRequest
{
    private final short role;
    private final short capver;
    private final int pid;
    private final String token;

    private String username;

    public LoginRequest(ByteBuf buffer)
    {
        super(buffer, kXR_login);

        int pos =
            buffer.indexOf(8, 16, (byte) 0); // User name is padded with '\0'
        if (pos > -1) {
            username = buffer.toString(8, pos - 8, US_ASCII);
        } else {
            username = buffer.toString(8, 8, US_ASCII);
        }

        pid = buffer.getInt(4);
        capver = buffer.getUnsignedByte(18);
        role = buffer.getUnsignedByte(19);

        int tlen = buffer.getInt(20);
        token = buffer.toString(24, tlen, US_ASCII);
    }

    public String getUserName()
    {
        return username;
    }

    public void setUserName(String username)
    {
        this.username = username;
    }

    public boolean supportsAsyn()
    {
        return (capver & 0x80) == 0x80;
    }

    public int getClientProtocolVersion()
    {
        return capver & 0x3f;
    }

    public boolean isAdmin()
    {
        return role == kXR_useradmin;
    }

    public int getPID()
    {
        return pid;
    }

    public String getToken()
    {
        return token;
    }

    @Override
    public String toString()
    {
        return "login[" + username + "," + pid + "," + capver + "," + role + "," + token + "]";
    }
}

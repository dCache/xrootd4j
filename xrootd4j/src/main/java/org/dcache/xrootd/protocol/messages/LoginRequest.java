/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.jboss.netty.buffer.ChannelBuffer;

public class LoginRequest extends XrootdRequest
{
    private final String _username;
    private final short _role;
    private final short _capver;
    private final int _pid;
    private final String _token;

    public LoginRequest(ChannelBuffer buffer)
    {
        super(buffer, kXR_login);

        int pos =
            buffer.indexOf(8, 16, (byte) 0); // User name is padded with '\0'
        if (pos > -1) {
            _username = buffer.toString(8, pos - 8, XROOTD_CHARSET);
        } else {
            _username = buffer.toString(8, 8, XROOTD_CHARSET);
        }

        _pid = buffer.getInt(4);
        _capver = buffer.getUnsignedByte(18);
        _role = buffer.getUnsignedByte(19);

        int tlen = buffer.getInt(20);
        _token = buffer.toString(24, tlen, XROOTD_CHARSET);
    }

    public String getUserName()
    {
        return _username;
    }

    public boolean supportsAsyn()
    {
        return (_capver & 0x80) == 0x80 ? true : false;
    }

    public int getClientProtocolVersion()
    {
        return _capver & 0x3f;
    }

    public boolean isAdmin()
    {
        return _role == kXR_useradmin ? true : false;
    }

    public int getPID()
    {
        return _pid;
    }

    public String getToken()
    {
        return _token;
    }
}

/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_useruser;

/**
 *  <p>The <code>token</code> field represents the rendezvous key given
 *         to the destination by the user client.</p>
 */
public class OutboundLoginRequest extends AbstractXrootdOutboundRequest
{
    protected final String username;
    protected final int pid;
    protected final String token;

    public OutboundLoginRequest(int streamId,
                                int pid,
                                String username,
                                String token)
    {
        super(streamId, kXR_login);
        this.pid = pid;
        this.username = username;
        this.token = token;
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        buffer.writeInt(pid);
        setPaddedUserName(username, buffer);
        // reserved
        buffer.writeByte(0);
        // ability –– nothing special
        buffer.writeByte(0);
        // capver –– 00000001 (no async, client v. 1);
        buffer.writeByte((0x00|0x01));
        // role = user
        buffer.writeByte(kXR_useruser);
        if (token != null) {
            buffer.writeInt(token.length());
            buffer.writeBytes(token.getBytes(US_ASCII));
        } else {
            buffer.writeInt(0);
        }
    }

    @Override
    protected int getParamsLen()
    {
        return 20 + (token == null ? 0 : token.length());
    }

    private static void setPaddedUserName(String name, ByteBuf buffer)
    {
        int len = name.length();
        byte[] ascii = name.getBytes(US_ASCII);
        for (int i = 0; i < 8; ++i) {
            if (i < len) {
                buffer.writeByte(ascii[i]);
            } else {
                buffer.writeByte(0);
            }
        }
    }
}

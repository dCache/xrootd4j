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

import org.dcache.xrootd.core.XrootdSessionIdentifier;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;

/**
 * <p>Response from third-party source server.</p>
 */
public class InboundLoginResponse extends AbstractXrootdInboundResponse
{
    private final XrootdSessionIdentifier sessionId;
    private final String                  sec;

    public InboundLoginResponse(ByteBuf buffer)
    {
        super(buffer);

        if (buffer.readableBytes() > 8) {
            int slen = buffer.getInt(4) - SESSION_ID_SIZE;
            byte[] session = new byte[SESSION_ID_SIZE];
            buffer.getBytes(8, session);
            sessionId = new XrootdSessionIdentifier(session);
            if (slen > 0) {
                sec = buffer.toString(24, slen, US_ASCII);
            } else {
                sec = null;
            }
        } else {
            sessionId = null;
            sec = null;
        }
    }

    public String getSec() {
        return sec;
    }

    public XrootdSessionIdentifier getSessionId() {
        return sessionId;
    }

    @Override
    public int getRequestId() {
        return kXR_login;
    }
}

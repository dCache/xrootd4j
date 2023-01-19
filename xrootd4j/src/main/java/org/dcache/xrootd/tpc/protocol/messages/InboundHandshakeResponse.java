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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_NotAuthorized;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_handshake;

/**
 * <p>Reply from third-party source server establishing connection.</p>
 */
public class InboundHandshakeResponse extends AbstractXrootdInboundResponse
{
    private final int pval;
    private final int flag;

    public InboundHandshakeResponse(ByteBuf buffer) throws XrootdException
    {
        super(buffer);
        int len = buffer.getInt(4);

        if (len < 8) {
            throw new XrootdException(kXR_NotAuthorized, "bad handshake");
        }

        pval = buffer.getInt(8);
        flag = buffer.getInt(12);
    }

    public int getFlag()
    {
        return flag;
    }

    public int getPval()
    {
        return pval;
    }

    @Override
    public int getRequestId()
    {
        return kXR_handshake;
    }
}

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

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.XrootdProtocol;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_handshake;

/**
 * <p>Reply from third-party source server establishing connection.</p>
 */
public class HandshakeResponse extends AbstractXrootdInboundResponse
{
    protected final int rlen;
    protected final int pval;
    protected final int flag;

    public HandshakeResponse(ByteBuf buffer) throws XrootdException
    {
        super(buffer);
        rlen = buffer.getInt(4);
        if (rlen != 8) {
            throw new XrootdException(XrootdProtocol.kXR_NotAuthorized,
                                      "handshake rlen was " + rlen);
        }
        pval = buffer.getInt(8);
        flag = buffer.getInt(12);
    }

    public int getFlag() {
        return flag;
    }

    public int getPval() {
        return pval;
    }

    @Override
    public int getRequestId() {
        return kXR_handshake;
    }
}

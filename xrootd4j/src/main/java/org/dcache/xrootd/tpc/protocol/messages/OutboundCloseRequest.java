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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_close;

/**
 * <p>Request to close file on the source server.</p>
 */
public class OutboundCloseRequest extends AbstractXrootdOutboundRequest
{
    private final int fhandle;

    public OutboundCloseRequest(int streamId, int fhandle)
    {
        super(streamId, kXR_close);
        this.fhandle = fhandle;
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        buffer.writeInt(fhandle);
        /*
         * The original open was read-only,
         * no need to enforce file size on the server end
         */
        buffer.writeLong(0);
        buffer.writeInt(0);
        buffer.writeInt(0);
    }

    @Override
    protected int getParamsLen() {
        return 20;
    }
}

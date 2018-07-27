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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

import org.dcache.xrootd.protocol.XrootdProtocol;

/**
 * <p>Initial handshake on a new connection.</p>
 */
public class OutboundHandshakeRequest implements XrootdOutboundRequest
{
    @Override
    public int getStreamId() {
        return 0;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        ByteBuf buffer = ctx.alloc().buffer(
                        XrootdProtocol.CLIENT_HANDSHAKE_LEN);
        try {
            buffer.writeBytes(XrootdProtocol.HANDSHAKE_REQUEST);
        } catch (Error | RuntimeException t) {
            promise.setFailure(t);
            buffer.release();
            return;
        }

        ctx.write(buffer, promise);
    }
}

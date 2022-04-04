/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

/**
 * <p>Supports outgoing client requests to the source server
 *      in third-party copies.</p>
 *
 * <p>According to protocol, all client requests must
 *      have the following packet structure:</p>
 *
 * <table>
 *     <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *     <tr><td>kXR_unt16</td><td>requestid</td></tr>
 *     <tr><td>kXR_char</td><td>parms[16]</td></tr>
 *     <tr><td>kXR_int32</td><td>dlen</td></tr>
 *     <tr><td>kXR_char</td><td>data[dlen]</td></tr>
 * </table>
 *
 * <p>For the purposes of the third-party-client, none of these make
 *    use of the data or data length fields.</p>
 */
public abstract class AbstractXrootdOutboundRequest implements
                XrootdOutboundRequest
{
    protected final int streamId;
    protected final int requestId;

    protected AbstractXrootdOutboundRequest(int streamId, int requestId)
    {
        this.streamId = streamId;
        this.requestId = requestId;
    }

    public int getStreamId()
    {
        return streamId;
    }

    public int getRequestId()
    {
        return requestId;
    }

    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        ByteBuf buffer = ctx.alloc().buffer(4 + getParamsLen());
        try {
            writeToBuffer(buffer);
        } catch (Error | RuntimeException t) {
            promise.setFailure(t);
            buffer.release();
            return;
        }
        ctx.write(buffer, promise);
    }

    protected void writeToBuffer(ByteBuf buffer) {
        buffer.writeShort(streamId);
        buffer.writeShort(requestId);
        getParams(buffer);
    }

    protected abstract void getParams(ByteBuf buffer);

    protected abstract int getParamsLen();


}

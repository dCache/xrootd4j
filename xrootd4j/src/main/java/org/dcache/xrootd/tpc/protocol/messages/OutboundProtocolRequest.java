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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>The kXR_protocol request has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_protocol</td></tr>
 *      <tr><td>kXR_int32</td><td>clientpv</td></tr>
 *      <tr><td>kXR_char</td><td>options</td></tr>
 *      <tr><td>kXR_char</td><td>expect</td></tr>
 *      <tr><td>kXR_char</td><td>reserved[10]</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *  </table>
 */
public class OutboundProtocolRequest implements XrootdOutboundRequest
{
    private static final byte[] RESERVED = {0,0,0,0,0,0,0,0,0,0};
    private int streamId;
    private int version;
    private int options;
    private int expect;

    public OutboundProtocolRequest(int streamId,
                                   int version,
                                   int options,
                                   int expect)
    {
        this.streamId = streamId;
        this.version = version;
        this.options = options;
        this.expect = expect;
    }

    @Override
    public int getStreamId() {
        return streamId;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        ByteBuf buffer = ctx.alloc().buffer(24);
        try {
            buffer.writeShort(streamId);
            buffer.writeShort(kXR_protocol);
            buffer.writeInt(version);
            buffer.writeByte(options);
            buffer.writeByte(expect);
            buffer.writeBytes(RESERVED);
            buffer.writeInt(0);
        } catch (Error | RuntimeException t) {
            promise.setFailure(t);
            buffer.release();
            return;
        }

        ctx.write(buffer, promise);
    }
}

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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCounted;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_oksofar;

public class ReadResponse implements XrootdResponse<ReadRequest>, ReferenceCounted
{
    private final ReadRequest request;
    private final int stat;
    private final ByteBuf data;

    public ReadResponse(ReadRequest request, ByteBuf data, boolean isIncomplete)
    {
        this.request = checkNotNull(request);
        this.stat = isIncomplete ? kXR_oksofar : kXR_ok;
        this.data = checkNotNull(data);
    }

    @Override
    public ReadRequest getRequest()
    {
        return request;
    }

    @Override
    public int getStatus()
    {
        return stat;
    }

    @Override
    public int getDataLength()
    {
        return data.readableBytes();
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        checkState(refCnt() > 0);

        ByteBuf header = ctx.alloc().buffer(8);
        header.writeShort(request.getStreamId());
        header.writeShort(stat);
        header.writeInt(data.readableBytes());

        ctx.write(ctx.alloc().compositeBuffer(2).addComponents(header, data).writerIndex(8 + data.readableBytes()), promise);
    }

    public ByteBuf getData()
    {
        return data.asReadOnly();
    }

    @Override
    public String toString()
    {
        return String.format("read-response[stat=%d,bytes=%d]", stat, data.readableBytes());
    }

    @Override
    public int refCnt()
    {
        return data.refCnt();
    }

    @Override
    public ReadResponse retain()
    {
        data.retain();
        return this;
    }

    @Override
    public ReadResponse retain(int increment)
    {
        data.retain(increment);
        return this;
    }

    @Override
    public boolean release()
    {
        return data.release();
    }

    @Override
    public boolean release(int decrement)
    {
        return data.release(decrement);
    }

    @Override
    public ReferenceCounted touch()
    {
        data.touch();
        return this;
    }

    @Override
    public ReferenceCounted touch(Object hint)
    {
        data.touch(hint);
        return this;
    }
}

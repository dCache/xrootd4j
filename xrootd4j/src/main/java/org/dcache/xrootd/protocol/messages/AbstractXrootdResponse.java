/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCountUtil;

import static com.google.common.base.Preconditions.checkNotNull;

public abstract class AbstractXrootdResponse<T extends XrootdRequest> implements XrootdResponse<T>
{
    protected final T request;
    protected final int stat;

    public AbstractXrootdResponse(T request, int stat)
    {
        this.request = checkNotNull(request);
        this.stat = stat;
    }

    @Override
    public T getRequest()
    {
        return request;
    }

    @Override
    public int getStatus()
    {
        return stat;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        ByteBuf buffer = ctx.alloc().buffer(getLength());
        try {
            getBytes(buffer);
            buffer.setInt(4, buffer.readableBytes() - 8);
        } catch (Error | RuntimeException t) {
            promise.setFailure(t);
            buffer.release();
        } finally {
            ReferenceCountUtil.release(this);
        }
        ctx.write(buffer, promise);
    }

    protected int getLength()
    {
        return 8;
    }

    protected void getBytes(ByteBuf buffer)
    {
        buffer.writeShort(request.getStreamId());
        buffer.writeShort(stat);
        buffer.writeInt(0);
    }
}

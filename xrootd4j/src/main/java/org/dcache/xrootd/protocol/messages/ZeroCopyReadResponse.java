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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.DefaultFileRegion;

import java.io.IOException;
import java.nio.channels.FileChannel;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;

public class ZeroCopyReadResponse implements XrootdResponse<ReadRequest>
{
    private final ReadRequest request;
    private final FileChannel file;
    private final int count;

    public ZeroCopyReadResponse(ReadRequest request, FileChannel file) throws IOException
    {
        this.request = checkNotNull(request);
        this.file = checkNotNull(file);
        this.count = (int) Math.min(request.bytesToRead(), file.size()  - request.getReadOffset());
    }

    @Override
    public ReadRequest getRequest()
    {
        return request;
    }

    @Override
    public int getStatus()
    {
        return kXR_ok;
    }

    @Override
    public int getDataLength()
    {
        return count;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, final ChannelPromise promise)
    {
        ByteBuf header = ctx.alloc().buffer(8);
        header.writeShort(request.getStreamId());
        header.writeShort(kXR_ok);
        header.writeInt(count);
        ctx.write(header).addListener(
                new ChannelFutureListener()
                {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception
                    {
                        if (!future.isSuccess()) {
                            promise.tryFailure(future.cause());
                        }
                    }
                });
        ctx.write(new DefaultFileRegion(file, request.getReadOffset(), count)).addListener(
                new ChannelFutureListener()
                {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception
                    {
                        if (future.isSuccess()) {
                            promise.trySuccess();
                        } else {
                            promise.tryFailure(future.cause());
                        }
                    }
                });
    }

    @Override
    public String toString()
    {
        return String.format("zero-copy-read-response[offset=%d,bytes=%d]", request.getReadOffset(), count);
    }
}

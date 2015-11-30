/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCountUtil;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asynresp;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_attn;

public class AsyncResponse<T extends XrootdRequest>
        extends AbstractReferenceCounted
        implements XrootdResponse<T>
{
    private final XrootdResponse<T> response;

    public AsyncResponse(XrootdResponse<T> response)
    {
        this.response = response;
    }

    @Override
    public int getStatus()
    {
        return response.getStatus();
    }

    public XrootdResponse<T> getResponse()
    {
        return response;
    }

    @Override
    public T getRequest()
    {
        return response.getRequest();
    }

    @Override
    public int getDataLength()
    {
        /* First 8 bytes are the header of kXR_attn and the next
         * 8 bytes are the header of the payload.
         */
        return 8 + 8 + response.getDataLength();
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, final ChannelPromise promise)
    {
        try {
            int dlen = getDataLength();
            ByteBuf header = ctx.alloc().buffer(8 + dlen);
            try {
                header.writeShort(0);
                header.writeShort(kXR_attn);
                header.writeInt(dlen);
                header.writeInt(kXR_asynresp);
                header.writeInt(0);
            } catch (Error | RuntimeException t) {
                promise.setFailure(t);
                header.release();
                return;
            }
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

            ChannelPromise channelPromise = ctx.newPromise();
            channelPromise.addListener(
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
            ReferenceCountUtil.retain(response).writeTo(ctx, channelPromise);
        } finally {
            release();
        }
    }

    @Override
    protected void deallocate()
    {
        ReferenceCountUtil.release(response);
    }
}

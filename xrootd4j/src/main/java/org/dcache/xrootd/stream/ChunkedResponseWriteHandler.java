/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
/* The file is based on ChunkedWriteHandler version 3.6.3 from the Netty Project.
 *
 * Copyright 2012 The Netty Project
 */
package org.dcache.xrootd.stream;

import io.netty.buffer.MessageBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.stream.ChunkedInput;
import io.netty.handler.stream.ChunkedWriteHandler;

import java.io.IOException;
import java.util.Queue;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;

public class ChunkedResponseWriteHandler extends ChunkedWriteHandler
{
    private MessageBuf<Object> queue;

    @Override
    public MessageBuf<Object> newOutboundBuffer(ChannelHandlerContext ctx) throws Exception {
        queue = super.newOutboundBuffer(ctx);
        return Unpooled.messageBuffer();
    }

    @Override
    public void freeOutboundBuffer(ChannelHandlerContext ctx) throws Exception {
        super.freeOutboundBuffer(ctx);
        ctx.outboundMessageBuffer().release();
    }

    @Override
    public void flush(ChannelHandlerContext ctx, ChannelPromise promise) throws Exception {
        Queue<Object> in = ctx.outboundMessageBuffer();
        Queue<Object> out = ctx.nextOutboundMessageBuffer();
        for (Object m = in.poll(); m != null; m = in.poll()) {
            if (m instanceof ChunkedInput) {
                queue.add(m);
            } else {
                out.add(m);
            }
        }
        super.flush(ctx, promise);
    }

    @Override
    protected boolean readChunk(ChannelHandlerContext ctx, ChunkedInput<?> chunks) throws Exception
    {
        try {
            return super.readChunk(ctx, chunks);
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.getMessage());
        }
    }
}

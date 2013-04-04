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
package org.dcache.xrootd.stream;

import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.ErrorResponse;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.jboss.netty.channel.Channels.fireExceptionCaught;
import static org.jboss.netty.channel.Channels.future;

/**
 * A {@link org.jboss.netty.channel.ChannelHandler} that adds support for writing chunked xrootd replies.
 *
 * Loosely based on Netty's ChunkedWriteHandler, but specialized for xrootd. Xrootd allows
 * replies to be delivered out of order, which means that unchunked responses do not have to be
 * queued and can be passed downstream right away.
 *
 * XrootdChunkedWriteHandler also implements read-ahead by fetching the next chunk even if the
 * channel is not writable.
 *
 * XrootdChunkedWriteHandler does not support suspended transfers.
 *
 * To use {@link ChunkedResponseWriteHandler}, you have to insert
 * a new {@link ChunkedResponseWriteHandler} instance:
 * <pre>
 * {@link org.jboss.netty.channel.ChannelPipeline} p = ...;
 * p.addLast("streamer", <b>new {@link ChunkedResponseWriteHandler}()</b>);
 * p.addLast("handler", new MyHandler());
 * </pre>
 * Once inserted, you can write a {@link ChunkedResponse} so that the
 * {@link ChunkedResponseWriteHandler} can pick it up and fetch the content of the
 * stream chunk by chunk and write the fetched chunk downstream:
 * <pre>
 * {@link org.jboss.netty.channel.Channel} ch = ...;
 * {@link org.dcache.xrootd.protocol.messages.ReadRequest} request = ...;
 * long maxFrameSize = 2 << 20;
 * {@link java.nio.channels.FileChannel} channel = ...;
 * ch.write(new {@link org.dcache.xrootd.stream.ChunkedFileChannelReadResponse}(request, maxFrameSize, channel));
 * </pre>
 *
 */
public class ChunkedResponseWriteHandler
    implements ChannelUpstreamHandler, ChannelDownstreamHandler
{
    private final static Logger logger =
        LoggerFactory.getLogger(ChunkedResponseWriteHandler.class);

    private final Queue<MessageEvent> queue =
        new ConcurrentLinkedQueue<MessageEvent>();

    private MessageEvent currentEvent;
    private Object nextChunk;
    private ChannelFuture nextFuture;

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e)
        throws Exception
    {
        if (!(e instanceof MessageEvent)) {
            ctx.sendDownstream(e);
            return;
        }

        Object m = ((MessageEvent) e).getMessage();
        if (!(m instanceof ChunkedResponse)) {
            ctx.sendDownstream(e);
            return;
        }

        queue.offer((MessageEvent) e);

        flush(ctx);
    }

    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e)
        throws Exception
    {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent cse = (ChannelStateEvent) e;
            switch (cse.getState()) {
            case INTEREST_OPS:
                // Continue writing when the channel becomes writable.
                flush(ctx);
                break;
            case OPEN:
                if (!Boolean.TRUE.equals(cse.getValue())) {
                    // Fail all pending writes
                    discard(ctx);
                }
                break;
            }
        }
        ctx.sendUpstream(e);
    }

    private synchronized void discard(ChannelHandlerContext ctx)
    {
        if (currentEvent == null) {
            currentEvent = queue.poll();
        }
        while (currentEvent != null) {
            MessageEvent event = currentEvent;
            currentEvent = null;

            closeInput((ChunkedResponse) event.getMessage());

            // Trigger a ClosedChannelException
            Channels.write(
                ctx, event.getFuture(), ChannelBuffers.EMPTY_BUFFER,
                event.getRemoteAddress());

            currentEvent = queue.poll();
        }
        nextChunk = null;
        nextFuture = null;
    }

    private synchronized void readNextChunk(ChannelHandlerContext ctx)
        throws Exception
    {
        if (currentEvent == null || currentEvent.getFuture().isDone() ||
            ((ChunkedResponse) currentEvent.getMessage()).isEndOfInput()) {
            currentEvent = queue.poll();
            if (currentEvent == null) {
                nextChunk = null;
                return;
            }
        }

        final MessageEvent event = this.currentEvent;
        ChunkedResponse chunks = (ChunkedResponse) event.getMessage();

        try {
            nextChunk = chunks.nextChunk();

            if (chunks.isEndOfInput()) {
                closeInput(chunks);
                nextFuture = event.getFuture();
            } else {
                nextFuture = future(ctx.getChannel());
                nextFuture.addListener(new ChannelFutureListener() {
                    public void operationComplete(ChannelFuture future)
                        throws Exception
                    {
                        if (!future.isSuccess()) {
                            event.getFuture().setFailure(future.getCause());
                            closeInput((ChunkedResponse) event.getMessage());
                        }
                    }
                });
            }
        } catch (final XrootdException e) {
            currentEvent = null;
            nextChunk = new ErrorResponse(chunks.getRequest(), e.getError(), e.getMessage());

            nextFuture = future(ctx.getChannel());
            nextFuture.addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future)
                    throws Exception
                {
                    event.getFuture().setFailure(e);
                    closeInput((ChunkedResponse) event.getMessage());
                }
            });
        } catch (final IOException e) {
            currentEvent = null;
            nextChunk = new ErrorResponse(chunks.getRequest(), kXR_IOError, e.getMessage());

            nextFuture = future(ctx.getChannel());
            nextFuture.addListener(new ChannelFutureListener()
            {
                public void operationComplete(ChannelFuture future)
                    throws Exception
                {
                    event.getFuture().setFailure(e);
                    closeInput((ChunkedResponse) event.getMessage());
                }
            });
        } catch (final Exception e) {
            currentEvent = null;
            nextChunk = new ErrorResponse(chunks.getRequest(), kXR_ServerError, e.getMessage());

            nextFuture = future(ctx.getChannel());
            nextFuture.addListener(new ChannelFutureListener()
            {
                public void operationComplete(ChannelFuture future)
                    throws Exception
                {
                    event.getFuture().setFailure(e);
                    closeInput((ChunkedResponse) event.getMessage());
                }
            });
        } catch (Throwable t) {
            currentEvent = null;
            nextChunk = null;

            event.getFuture().setFailure(t);
            fireExceptionCaught(ctx, t);

            closeInput(chunks);
        }
    }

    private synchronized void flush(ChannelHandlerContext ctx) throws Exception
    {
        final Channel channel = ctx.getChannel();
        if (!channel.isConnected()) {
            discard(ctx);
        }

        if (nextChunk == null) {
            readNextChunk(ctx);
        }

        while (nextChunk != null && channel.isWritable()) {
            Channels.write(
                ctx, nextFuture, nextChunk,
                currentEvent.getRemoteAddress());

            readNextChunk(ctx);

            if (!channel.isConnected()) {
                discard(ctx);
                break;
            }
        }
    }

    static void closeInput(ChunkedResponse chunks) {
        try {
            chunks.close();
        } catch (Throwable t) {
            logger.warn("Failed to close a chunked response.", t);
        }
    }
}

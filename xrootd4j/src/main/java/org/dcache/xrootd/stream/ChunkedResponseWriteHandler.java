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
/* The file is based on ChunkedWriteHandler version 3.6.3 from the Netty Project.
 *
 * Copyright 2012 The Netty Project
 */
package org.dcache.xrootd.stream;

import com.google.common.base.Strings;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ChannelUpstreamHandler;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.ErrorResponse;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.jboss.netty.channel.Channels.*;

/**
 * A {@link org.jboss.netty.channel.ChannelHandler} that adds support for writing chunked xrootd replies.
 *
 * Loosely based on org.jboss.netty.handler.stream.ChunkedWriteHandler, but specialized for xrootd.
 * Xrootd allows replies to be delivered out of order, which means that unchunked responses do not
 * have to be queued and can be passed downstream right away.
 *
 * Since the handler is protocol specific, it can generated proper xrootd error responses in case
 * of faults.
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
 * Once inserted, you can write a {@link org.dcache.xrootd.stream.ChunkedResponse} so that the
 * {@link ChunkedResponseWriteHandler} can pick it up and fetch the content of the
 * stream chunk by chunk and write the fetched chunk downstream:
 * <pre>
 * {@link org.jboss.netty.channel.Channel} ch = ...;
 * {@link org.dcache.xrootd.protocol.messages.ReadRequest} request = ...;
 * long maxFrameSize = 2 << 20;
 * {@link java.nio.channels.FileChannel} channel = ...;
 * ch.write(new {@link ChunkedFileChannelReadResponse}(request, maxFrameSize, channel));
 * </pre>
 *
 */
public class ChunkedResponseWriteHandler
    implements ChannelUpstreamHandler, ChannelDownstreamHandler, LifeCycleAwareChannelHandler
{
    private static final Logger logger =
        LoggerFactory.getLogger(ChunkedResponseWriteHandler.class);

    private final Queue<MessageEvent> queue = new ConcurrentLinkedQueue<>();

    private final AtomicBoolean flush = new AtomicBoolean(false);
    private MessageEvent currentEvent;
    private volatile boolean flushNeeded;

    @Override
    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent e)
            throws Exception {
        if (!(e instanceof MessageEvent)) {
            ctx.sendDownstream(e);
            return;
        }

        Object m = ((MessageEvent) e).getMessage();
        if (!(m instanceof ChunkedResponse)) {
            ctx.sendDownstream(e);
            return;
        }

        boolean offered = queue.offer((MessageEvent) e);
        assert offered;

        final Channel channel = ctx.getChannel();
        // call flush if the channel is writable or not connected. flush(..) will take care of the rest

        if (channel.isWritable() || !channel.isConnected()) {
            flush(ctx, false);
        }
    }

    @Override
    public void handleUpstream(ChannelHandlerContext ctx, ChannelEvent e)
            throws Exception {
        if (e instanceof ChannelStateEvent) {
            ChannelStateEvent cse = (ChannelStateEvent) e;
            switch (cse.getState()) {
            case INTEREST_OPS:
                // Continue writing when the channel becomes writable.
                flush(ctx, true);
                break;
            case OPEN:
                if (!Boolean.TRUE.equals(cse.getValue())) {
                    // Fail all pending writes
                    flush(ctx, true);
                }
                break;
            }
        }
        ctx.sendUpstream(e);
    }

    private void discard(ChannelHandlerContext ctx, boolean fireNow) {
        ClosedChannelException cause = null;

        for (;;) {
            MessageEvent currentEvent = this.currentEvent;

            if (this.currentEvent == null) {
                currentEvent = queue.poll();
            } else {
                this.currentEvent = null;
            }

            if (currentEvent == null) {
                break;
            }

            closeInput((ChunkedResponse) currentEvent.getMessage());

            // Trigger a ClosedChannelException
            if (cause == null) {
                cause = new ClosedChannelException();
            }
            currentEvent.getFuture().setFailure(cause);
        }

        if (cause != null) {
            if (fireNow) {
                fireExceptionCaught(ctx.getChannel(), cause);
            } else {
                fireExceptionCaughtLater(ctx.getChannel(), cause);
            }
        }
    }

    private void flush(ChannelHandlerContext ctx, boolean fireNow) throws Exception {
        boolean acquired;
        final Channel channel = ctx.getChannel();
        flushNeeded = true;
        // use CAS to see if the have flush already running, if so we don't need to take further actions
        if (acquired = flush.compareAndSet(false, true)) {
            flushNeeded = false;
            try {
                if (!channel.isConnected()) {
                    discard(ctx, fireNow);
                    return;
                }

                while (channel.isWritable()) {
                    if (currentEvent == null) {
                        currentEvent = queue.poll();
                    }

                    if (currentEvent == null) {
                        break;
                    }

                    if (currentEvent.getFuture().isDone()) {
                        // Skip the current request because the previous partial write
                        // attempt for the current request has been failed.
                        currentEvent = null;
                    } else {
                        final MessageEvent currentEvent = this.currentEvent;
                        final ChunkedResponse chunks = (ChunkedResponse) currentEvent.getMessage();
                        Object chunk;
                        boolean endOfInput;
                        try {
                            chunk = chunks.nextChunk();
                            endOfInput = chunks.isEndOfInput();
                        } catch (XrootdException e) {
                            currentEvent.getFuture().setFailure(e);
                            chunk = new ErrorResponse(chunks.getRequest(), e.getError(),
                                    Strings.nullToEmpty(e.getMessage()));
                            endOfInput = true;
                        } catch (IOException e) {
                            logger.warn("xrootd I/O error: {}", e.toString());
                            currentEvent.getFuture().setFailure(e);
                            chunk = new ErrorResponse(chunks.getRequest(), kXR_IOError,
                                    Strings.nullToEmpty(e.getMessage()));
                            endOfInput = true;
                        } catch (RuntimeException e) {
                            logger.error("xrootd server error (please report this to support@dcache.org)", e);
                            currentEvent.getFuture().setFailure(e);
                            chunk = new ErrorResponse(chunks.getRequest(), kXR_ServerError,
                                    Strings.nullToEmpty(e.getMessage()));
                            endOfInput = true;
                        } catch (Exception e) {
                            logger.warn("xrootd server error: {}", e.toString());
                            currentEvent.getFuture().setFailure(e);
                            chunk = new ErrorResponse(chunks.getRequest(), kXR_ServerError,
                                    Strings.nullToEmpty(e.getMessage()));
                            endOfInput = true;
                        } catch (Error t) {
                            this.currentEvent = null;

                            currentEvent.getFuture().setFailure(t);
                            if (fireNow) {
                                fireExceptionCaught(ctx, t);
                            } else {
                                fireExceptionCaughtLater(ctx, t);
                            }

                            closeInput(chunks);
                            break;
                        }

                        ChannelFuture writeFuture;
                        if (endOfInput) {
                            this.currentEvent = null;
                            writeFuture = currentEvent.getFuture();

                            // Register a listener which will close the input once the write
                            // is complete. This is needed because the Chunk may have some
                            // resource bound that can not be closed before its not written
                            //
                            // See https://github.com/netty/netty/issues/303
                            writeFuture.addListener(new ChannelFutureListener() {

                                public void operationComplete(ChannelFuture future) throws Exception {
                                    closeInput(chunks);
                                }
                            });
                        } else {
                            writeFuture = future(channel);
                            writeFuture.addListener(new ChannelFutureListener() {
                                public void operationComplete(ChannelFuture future) throws Exception {
                                    if (!future.isSuccess()) {
                                        currentEvent.getFuture().setFailure(future.getCause());
                                        closeInput((ChunkedResponse) currentEvent.getMessage());
                                    }
                                }
                            });
                        }

                        write(
                                ctx, writeFuture, chunk,
                                currentEvent.getRemoteAddress());
                    }

                    if (!channel.isConnected()) {
                        discard(ctx, fireNow);
                        return;
                    }
                }
            } finally {
                // mark the flush as done
                flush.set(false);
            }
        }

        if (acquired && (!channel.isConnected() || channel.isWritable() && !queue.isEmpty() || flushNeeded)) {
            flush(ctx, fireNow);
        }
    }

    static void closeInput(ChunkedResponse chunks) {
        try {
            chunks.close();
        } catch (Throwable t) {
            logger.warn("Failed to close a chunked input.", t);
        }
    }

    @Override
    public void beforeAdd(ChannelHandlerContext ctx) throws Exception {
        // nothing to do
    }

    @Override
    public void afterAdd(ChannelHandlerContext ctx) throws Exception {
        // nothing to do
    }

    @Override
    public void beforeRemove(ChannelHandlerContext ctx) throws Exception {
        // try to flush again a last time.
        //
        // See #304
        flush(ctx, false);
    }

    // This method should not need any synchronization as the ChunkedWriteHandler will not receive any new events
    @Override
    public void afterRemove(ChannelHandlerContext ctx) throws Exception {
        // Fail all MessageEvent's that are left. This is needed because otherwise we would never notify the
        // ChannelFuture and the registered FutureListener. See #304
        Throwable cause = null;
        boolean fireExceptionCaught = false;

        for (;;) {
            MessageEvent currentEvent = this.currentEvent;

            if (this.currentEvent == null) {
                currentEvent = queue.poll();
            } else {
                this.currentEvent = null;
            }

            if (currentEvent == null) {
                break;
            }

            closeInput((ChunkedResponse) currentEvent.getMessage());

            // Create exception
            if (cause == null) {
                cause = new IOException("Unable to flush event, discarding");
            }
            currentEvent.getFuture().setFailure(cause);
            fireExceptionCaught = true;
        }

        if (fireExceptionCaught) {
            fireExceptionCaughtLater(ctx.getChannel(), cause);
        }
    }
}

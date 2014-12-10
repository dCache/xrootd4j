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
/* The file is based on ChunkedWriteHandler version 4.0.24 from the Netty Project.
 *
 * Copyright 2012 The Netty Project
 */
package org.dcache.xrootd.stream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelProgressivePromise;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.channels.ClosedChannelException;
import java.util.ArrayDeque;
import java.util.Queue;

/**
 * A {@link io.netty.channel.ChannelHandler} that adds support for writing chunked xrootd replies.
 *
 * Loosely based on io.netty.handler.stream.ChunkedWriteHandler, but specialized for xrootd.
 * Xrootd allows replies to be delivered out of order, which means that unchunked responses do not
 * have to be queued and can be passed downstream right away.
 *
 * Since the handler is protocol specific, it can generated proper xrootd error responses in case
 * of faults.
 *
 * ChunkedResponseWriteHandler does not support suspended transfers.
 *
 * To use {@link ChunkedResponseWriteHandler}, you have to insert
 * a new {@link ChunkedResponseWriteHandler} instance:
 * <pre>
 * {@link io.netty.channel.ChannelPipeline} p = ...;
 * p.addLast("streamer", <b>new {@link ChunkedResponseWriteHandler}()</b>);
 * p.addLast("handler", new MyHandler());
 * </pre>
 * Once inserted, you can write a {@link org.dcache.xrootd.stream.ChunkedResponse} so that the
 * {@link ChunkedResponseWriteHandler} can pick it up and fetch the content of the
 * stream chunk by chunk and write the fetched chunk downstream:
 * <pre>
 * {@link io.netty.channel.Channel} ch = ...;
 * {@link org.dcache.xrootd.protocol.messages.ReadRequest} request = ...;
 * long maxFrameSize = 2 << 20;
 * {@link java.nio.channels.FileChannel} channel = ...;
 * ch.write(new {@link ChunkedFileChannelReadResponse}(request, maxFrameSize, channel));
 * </pre>
 *
 */
public class ChunkedResponseWriteHandler
        extends ChannelDuplexHandler
{
    private static final Logger logger =
            LoggerFactory.getLogger(ChunkedResponseWriteHandler.class);

    private final Queue<PendingWrite> queue = new ArrayDeque<>();
    private PendingWrite currentWrite;

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception
    {
        if (msg instanceof ChunkedResponse) {
            queue.add(new PendingWrite((ChunkedResponse) msg, promise));
        } else {
            ctx.write(msg, promise);
        }
    }

    @Override
    public void flush(ChannelHandlerContext ctx) throws Exception
    {
        if (queue.isEmpty()) {
            ctx.flush();
        } else {
            Channel channel = ctx.channel();
            if (channel.isWritable() || !channel.isActive()) {
                doFlush(ctx);
            }
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception
    {
        doFlush(ctx);
        super.channelInactive(ctx);
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception
    {
        if (ctx.channel().isWritable()) {
            // channel is writable again try to continue flushing
            doFlush(ctx);
        }
        ctx.fireChannelWritabilityChanged();
    }

    private void discard(Throwable cause)
    {
        for (;;) {
            PendingWrite currentWrite = this.currentWrite;

            if (this.currentWrite == null) {
                currentWrite = queue.poll();
            } else {
                this.currentWrite = null;
            }

            if (currentWrite == null) {
                break;
            }
            ChunkedResponse in = currentWrite.msg;
            try {
                if (!in.isEndOfInput()) {
                    if (cause == null) {
                        cause = new ClosedChannelException();
                    }
                    currentWrite.fail(cause);
                } else {
                    currentWrite.success();
                }
            } catch (Exception e) {
                currentWrite.fail(e);
                logger.warn(ChunkedResponse.class.getSimpleName() + ".isEndOfInput() failed", e);
            }
        }
    }

    private void doFlush(final ChannelHandlerContext ctx) throws Exception
    {
        final Channel channel = ctx.channel();
        if (!channel.isActive()) {
            discard(null);
            return;
        }
        while (channel.isWritable()) {
            if (currentWrite == null) {
                currentWrite = queue.poll();
            }

            if (currentWrite == null) {
                break;
            }
            final PendingWrite currentWrite = this.currentWrite;
            final ChunkedResponse pendingMessage = currentWrite.msg;

            boolean endOfInput;
            Object message = null;
            try {
                message = pendingMessage.nextChunk(ctx.alloc());
                endOfInput = pendingMessage.isEndOfInput();
            } catch (final Throwable t) {
                this.currentWrite = null;

                if (message != null) {
                    ReferenceCountUtil.release(message);
                }

                currentWrite.fail(t);
                break;
            }

            if (message == null) {
                // If message is null write an empty ByteBuf.
                // See https://github.com/netty/netty/issues/1671
                message = Unpooled.EMPTY_BUFFER;
            }

            final int amount = amount(message);
            ChannelFuture f = ctx.write(message);
            if (endOfInput) {
                this.currentWrite = null;

                // Register a listener which will close the input once the write is complete.
                // This is needed because the Chunk may have some resource bound that can not
                // be closed before its not written.
                //
                // See https://github.com/netty/netty/issues/303
                f.addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (!future.isSuccess()) {
                            currentWrite.fail(future.cause());
                        } else {
                            currentWrite.progress(amount);
                            currentWrite.success();
                        }
                    }
                });
            } else {
                f.addListener(new ChannelFutureListener() {
                    @Override
                    public void operationComplete(ChannelFuture future) throws Exception {
                        if (!future.isSuccess()) {
                            currentWrite.fail(future.cause());
                        } else {
                            currentWrite.progress(amount);
                        }
                    }
                });
            }

            // Always need to flush
            ctx.flush();

            if (!channel.isActive()) {
                discard(new ClosedChannelException());
                return;
            }
        }
    }

    private static final class PendingWrite {
        final ChunkedResponse msg;
        final ChannelPromise promise;
        private long progress;

        PendingWrite(ChunkedResponse msg, ChannelPromise promise) {
            this.msg = msg;
            this.promise = promise;
        }

        void closeInput() {
            try {
                msg.close();
            } catch (Throwable t) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Failed to close a chunked input.", t);
                }
            }
            ReferenceCountUtil.release(msg);
        }

        void fail(Throwable cause) {
            closeInput();
            promise.tryFailure(cause);
        }

        void success() {
            closeInput();
            if (promise.isDone()) {
                // No need to notify the progress or fulfill the promise because it's done already.
                return;
            }

            if (promise instanceof ChannelProgressivePromise) {
                // Now we know what the total is.
                ((ChannelProgressivePromise) promise).tryProgress(progress, progress);
            }

            promise.trySuccess();
        }

        void progress(int amount) {
            progress += amount;
            if (promise instanceof ChannelProgressivePromise) {
                ((ChannelProgressivePromise) promise).tryProgress(progress, -1);
            }
        }
    }

    private static int amount(Object msg) {
        if (msg instanceof ByteBuf) {
            return ((ByteBuf) msg).readableBytes();
        }
        if (msg instanceof ByteBufHolder) {
            return ((ByteBufHolder) msg).content().readableBytes();
        }
        return 1;
    }
}

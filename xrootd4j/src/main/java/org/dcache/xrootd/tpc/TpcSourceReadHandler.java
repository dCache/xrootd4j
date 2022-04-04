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
package org.dcache.xrootd.tpc;

import io.netty.channel.ChannelHandlerContext;
import io.netty.util.ReferenceCountUtil;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundChecksumResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundChecksumRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundReadRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>This handler reads until the file is complete, terminating the session
 *      thereafter.  When complete, it uses the write handler on its client to
 *      send a reply to the kXR_sync request received from the initiating client,
 *      and calls back to disconnect the third-party client.</p>
 *
 * <p>Optional checksum verification (done prior to the sync reply)
 *    is implemented by subclasses.</p>
 */
public abstract class TpcSourceReadHandler extends AbstractClientSourceHandler
{
    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_read:
                sendReadRequest(ctx);
                break;
            case kXR_query:
                sendChecksumRequest(ctx);
                break;
            default:
                super.doOnAsynResponse(ctx, response);
        }
    }

    @Override
    protected void doOnChecksumResponse(ChannelHandlerContext ctx,
                                        InboundChecksumResponse response)
                    throws XrootdException
    {
        int status = response.getStatus();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("Checksum query response for {} on {}, channel {}, stream {} "
                                     + "received, status {}.",
                     tpcInfo.getLfn(),
                     tpcInfo.getSrc(),
                     ctx.channel().id(),
                     client.getStreamId(),
                     status);
        if (status != kXR_ok) {
            String error = String.format("Checksum query for %s failed.",
                                         tpcInfo.getLfn());
            handleTransferTerminated(status, error, ctx);
            return;
        }

        validateChecksum(response, ctx);
    }

    @Override
    protected void doOnReadResponse(ChannelHandlerContext ctx,
                                    InboundReadResponse response)
    {
        try {
            XrootdTpcInfo tpcInfo = client.getInfo();
            long fileSize;

            try {
                fileSize = tpcInfo.computeFileSize();
            } catch (XrootdException e) {
                handleTransferTerminated(kXR_ArgMissing, e.toString(), ctx);
                return;
            }

            int status = response.getStatus();
            int bytesRcvd = response.getDlen();
            LOGGER.debug("Read response received for {} on {}, channel {}, "
                                         + "stream {}: status {}, "
                                         + "got {} more bytes.",
                         tpcInfo.getLfn(),
                         tpcInfo.getSrc(),
                         ctx.channel().id(),
                         client.getStreamId(),
                         status,
                         bytesRcvd);

            if (status != kXR_ok && status != kXR_oksofar) {
                String error = String.format(
                                "Read of %s failed with status %s.",
                                tpcInfo.getLfn(), status);
                handleTransferTerminated(kXR_error, error, ctx);
                return;
            }

            long writeOffset = client.getWriteOffset();
            long remaining = fileSize - writeOffset;

            if (bytesRcvd > remaining) {
                LOGGER.error("client received from the source "
                                             + "server {} bytes past EOF.",
                             bytesRcvd-remaining);
            }

            if (bytesRcvd > 0) {
                try {
                    response.setWriteOffset(writeOffset);
                    client.getWriteHandler().write(response);
                    writeOffset += bytesRcvd;
                    client.setWriteOffset(writeOffset);
                } catch (ClosedChannelException e) {
                    handleTransferTerminated(kXR_ServerError, "Channel "
                                                             + ctx.channel().id()
                                                             + " was forcefully "
                                                             + "closed by the server.",
                                             ctx);
                    return;
                } catch (IOException e) {
                    handleTransferTerminated(kXR_IOError, e.toString(), ctx);
                    return;
                }

                LOGGER.debug("Read of {} on {}, channel {}, stream {}: "
                                             + "wrote {}, "
                                             + "so far {}, expected {}.",
                             tpcInfo.getLfn(),
                             tpcInfo.getSrc(),
                             ctx.channel().id(),
                             client.getStreamId(),
                             bytesRcvd,
                             writeOffset,
                             fileSize);
            }

            if (status == kXR_oksofar) {
                LOGGER.debug("Waiting for more data for {} on {}, "
                                             + "channel {}, stream {}",
                             tpcInfo.getLfn(),
                             tpcInfo.getSrc(),
                             ctx.channel().id(),
                             client.getStreamId());
                return;
            }

            if (writeOffset < fileSize) {
                sendReadRequest(ctx);
            } else if (tpcInfo.getCks() != null) {
                sendChecksumRequest(ctx);
            } else {
                LOGGER.debug("Read for {} on {}, channel {}, stream {},"
                                             + " completed without "
                                             + "checksum verification.",
                             tpcInfo.getLfn(),
                             tpcInfo.getSrc(),
                             ctx.channel().id(),
                             client.getStreamId());
                handleTransferTerminated(kXR_ok, null, ctx);
            }
       } finally {
            ReferenceCountUtil.release(response);
        }
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_read:
                client.getExecutor().schedule(() -> {
                    sendReadRequest(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            case kXR_query:
                client.getExecutor().schedule(() -> {
                    sendChecksumRequest(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            default:
                super.doOnWaitResponse(ctx, response);
        }
    }

    protected void handleTransferTerminated(int status,
                                            String error,
                                            ChannelHandlerContext ctx)
    {
        client.getWriteHandler().fireDelayedSync(status, error);
        LOGGER.debug("handleTransferTerminated called fire delayed sync, "
                                     + "calling client shutdown");
        client.shutDown(ctx);
    }

    @Override
    protected void sendReadRequest(ChannelHandlerContext ctx)
    {
        XrootdTpcInfo tpcInfo = client.getInfo();
        int requestBlock;
        try {
            long remaining = tpcInfo.computeFileSize() - client.getWriteOffset();

            if (remaining < 0) {
                throw new XrootdException(kXR_IOError,
                                          "tpc request has written beyond EOF.");
            }

            requestBlock = (int)Math.min(getChunkSize(), remaining);
            LOGGER.debug("sendReadRequest to {}, channel {}, stream {}, "
                          + "fhandle {}, offset {}, requested block {}.",
                         tpcInfo.getSrc(),
                         ctx.channel().id(),
                         client.getStreamId(),
                         client.getFhandle(),
                         client.getWriteOffset(),
                         requestBlock);
            client.setExpectedResponse(kXR_read);
        } catch (XrootdException e) {
            exceptionCaught(ctx, e);
            return;
        }

        ctx.writeAndFlush(new OutboundReadRequest(client.getStreamId(),
                                                  client.getFhandle(),
                                                  client.getWriteOffset(),
                                                  requestBlock),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }

    @Override
    protected void sendChecksumRequest(ChannelHandlerContext ctx)
    {
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("sendChecksumRequest to {}, channel {}, "
                                     + "stream {}, fhandle {}.",
                     tpcInfo.getSrc(),
                     ctx.channel().id(),
                     client.getStreamId(),
                     client.getFhandle());
        client.setExpectedResponse(kXR_query);
        ctx.writeAndFlush(new OutboundChecksumRequest(client.getStreamId(),
                                                      tpcInfo.getLfn()),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }

    protected abstract void validateChecksum(InboundChecksumResponse response,
                                             ChannelHandlerContext ctx)
                    throws XrootdException;

    protected abstract int getChunkSize();
}

/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
import io.netty.channel.ChannelId;

import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundChecksumResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundCloseResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundOpenReadOnlyResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundOpenReadOnlyRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>Xrootd Third Party copy requires the destination server to be active,
 *    and request a read of the source file from the source server.</p>
 *
 * <p>This handler implements open and close.</p>
 *
 * <p>Concrete implementations must handle the actual read and checksum
 *    requests and responses.</p>
 *
 * <p>If the close response is OK, it hands it off to the next handler
 *    in the chain.</p>
 */
public abstract class AbstractClientSourceHandler extends
                AbstractClientRequestHandler
{
    /**
     * <p>If the response contains a security context, then
     *    it was not handled by an authentication plugin, and the
     *    transfer should fail.</p>
     */
    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
        throws XrootdException
    {
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("login response to {} received, channel {}, stream {}.",
                     tpcInfo.getSrc(),
                     id,
                     client.getStreamId());
        if (!response.getProtocols().isEmpty()) {
            String error = String.format("Authentication to %s failed; "
                            + "all protocols have been tried.",
                                         tpcInfo.getSrc());
            throw new XrootdException(kXR_NotAuthorized, error);
        } else {
            LOGGER.debug("login of {} on {}, channel {}, stream {}, complete, "
                                         + "proceeding to open.",
                         tpcInfo.getLfn(),
                         tpcInfo.getSrc(),
                         id,
                         client.getStreamId());
            sendOpenRequest(ctx);
        }
    }

    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_open:
                sendOpenRequest(ctx);
                break;
            case kXR_close:
                client.doClose(ctx);
                break;
            default:
                super.doOnAsynResponse(ctx, response);
        }
    }

    /**
     * <p>If this method is called on this handler with status OK,
     *    this means that step has succeeded.</p>
     */
    @Override
    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
                                              InboundAuthenticationResponse response)
                    throws XrootdException
    {
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("authentication of {} on {}, channel {}, stream {}, complete,"
                                     + " proceeding to open.",
                     tpcInfo.getLfn(),
                     tpcInfo.getSrc(),
                     id,
                     client.getStreamId());
        sendOpenRequest(ctx);
    }

    @Override
    protected void doOnCloseResponse(ChannelHandlerContext ctx,
                                     InboundCloseResponse response)
                    throws XrootdException
    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("Close response for {} on {}, channel {}, stream {}, "
                                     + "received with status {}.",
                     tpcInfo.getLfn(),
                     tpcInfo.getSrc(),
                     id,
                     client.getStreamId(),
                     status);
        switch (status) {
            case kXR_ok:
                LOGGER.debug("Close of {} on {}, channel {}, stream {}, "
                                             + "succeeded, ending session.",
                             tpcInfo.getLfn(),
                             tpcInfo.getSrc(),
                             id,
                             client.getStreamId());
                client.doEndsession(ctx);
                break;
            default:
                String error = String.format("Close of %s on %s failed "
                                                             + "with status %s.",
                                             tpcInfo.getLfn(),
                                             tpcInfo.getSrc(),
                                             status);
                throw new XrootdException(kXR_IOError, error);
        }

        client.setOpenFile(false);
    }

    @Override
    protected void doOnOpenResponse(ChannelHandlerContext ctx,
                                    InboundOpenReadOnlyResponse response)
                    throws XrootdException
    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("Open response for {} on {} received, channel {}, stream {}, "
                                     + "fhandle {}, cpsize {}, cptype {}; status {}.",
                     tpcInfo.getLfn(),
                     tpcInfo.getSrc(),
                     id,
                     client.getStreamId(),
                     response.getFhandle(),
                     response.getCpsize(),
                     response.getCptype(),
                     status);
        if (status == kXR_ok) {
            client.setOpenFile(true);
            client.setFhandle(response.getFhandle());
            client.setCpsize(response.getCpsize());
            client.setCptype(response.getCptype());
            tpcInfo.setFileStatus(response.getFileStatus());
            sendReadRequest(ctx);
        } else {
            String error = String.format("Open of %s on %s failed with status %s.",
                                         tpcInfo.getLfn(),
                                         tpcInfo.getSrc(),
                                         status);
            throw new XrootdException(kXR_IOError, error);
        }
    }

    @Override
    protected void sendOpenRequest(ChannelHandlerContext ctx)
    {
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("sendOpenRequest to {}, channel {}, stream {}, "
                                     + "path {}.",
                     tpcInfo.getSrc(),
                     ctx.channel().id(),
                     client.getStreamId(),
                     client.getFullpath());
        client.setExpectedResponse(kXR_open);
        ctx.writeAndFlush(new OutboundOpenReadOnlyRequest(client.getStreamId(),
                                                          client.getFullpath()),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_open:
                client.getExecutor().schedule(() -> {
                    sendOpenRequest(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            case kXR_close:
                client.getExecutor().schedule(() -> {
                    client.doClose(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            default:
                super.doOnWaitResponse(ctx, response);
        }
    }

    /**
     *  Should check the checksum and fail or succeed accordingly.
     */
    @Override
    protected abstract void doOnChecksumResponse(ChannelHandlerContext ctx,
                                                 InboundChecksumResponse response)
                    throws XrootdException;

    /**
     *  Should implement the proper read logic.  If vector reads are supported,
     *  should direct to special method.
     */
    @Override
    protected abstract void doOnReadResponse(ChannelHandlerContext ctx,
                                             InboundReadResponse response)
                    throws XrootdException;

    /**
     *  If checksum option is expressed.
     */
    @Override
    protected abstract void sendChecksumRequest(ChannelHandlerContext ctx)
                    throws XrootdException;

    /**
     *  Should take care of any special handling, such as vectorization.
     */
    @Override
    protected abstract void sendReadRequest(ChannelHandlerContext ctx)
                    throws XrootdException;
}

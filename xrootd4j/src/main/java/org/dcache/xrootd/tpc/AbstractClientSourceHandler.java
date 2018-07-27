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
     * <p>If this method is called on this handler with status OK,
     *    this means that step has succeeded.</p>
     *
     * <p>If the response contains a security context, however, then
     *    it was not handled by an authentication plugin, and the
     *    transfer should fail.</p>
     */
    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
    {
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.trace("login of {} on {}, channel {}, stream {}, complete, "
                                     + "proceeding to open.",
                     tpcInfo.getLfn(),
                     tpcInfo.getSrc(),
                     id,
                     client.getStreamId());
        String sec = response.getSec();
        if (sec != null) {
            String error = String.format("Authentication of %s on %s, "
                            + "channel %s, stream %d, is required; "
                            + "not handled.",
                                         tpcInfo.getLfn(),
                                         tpcInfo.getSrc(),
                                         id,
                                         client.getStreamId());
            exceptionCaught(ctx,
                            new XrootdException(kXR_error, error));
        } else {
            sendOpenRequest(ctx);
        }
    }

    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
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
    {
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.trace("authentication of {} on {}, channel {}, stream {}, complete,"
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
    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        switch (status) {
            case kXR_ok:
                LOGGER.trace("Close of {} on {}, channel {}, stream {}, "
                                             + "succeeded, ending session.",
                             tpcInfo.getLfn(),
                             tpcInfo.getSrc(),
                             id,
                             client.getStreamId());
                client.doEndsession(ctx);
                break;
            default:
                String error = String.format("Close of %s on %s, channel %s, "
                                                             + "stream %d, failed: "
                                                             + "status %d.",
                                             tpcInfo.getLfn(),
                                             tpcInfo.getSrc(),
                                             id,
                                             client.getStreamId(),
                                             status);
                exceptionCaught(ctx,
                                new XrootdException(kXR_error, error));
        }

        client.setOpenFile(false);
    }

    @Override
    protected void doOnOpenResponse(ChannelHandlerContext ctx,
                                    InboundOpenReadOnlyResponse response)

    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        XrootdTpcInfo tpcInfo = client.getInfo();
        if (status == kXR_ok) {
            client.setOpenFile(true);
            client.setFhandle(response.getFhandle());
            client.setCpsize(response.getCpsize());
            client.setCptype(response.getCptype());
            LOGGER.trace("Open of {} on {}, channel {}, stream {}, succeeded, "
                                         + "fhandle {}, cpsize {}, cptype {}.",
                         tpcInfo.getLfn(),
                         tpcInfo.getSrc(),
                         id,
                         client.getStreamId(),
                         client.getFhandle(),
                         client.getCpsize(),
                         client.getCptype());
            sendReadRequest(ctx);
        } else {
            String error = String.format(
                            "Open of %s on %s, channel %s, "
                                            + "stream %d, failed: "
                                            + "status %d.",
                            tpcInfo.getLfn(),
                            tpcInfo.getSrc(),
                            id,
                            client.getStreamId(),
                            status);
            exceptionCaught(ctx,
                            new XrootdException(kXR_error, error));
        }
    }

    @Override
    protected void sendOpenRequest(ChannelHandlerContext ctx)
    {
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.trace("sendOpenRequest to {}, channel {}, stream {}, "
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
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
    {
        switch (response.getRequestId()) {
            case kXR_open:
                client.getExecutor().schedule(new Runnable() {
                                                  @Override
                                                  public void run() {
                                                      sendOpenRequest(ctx);
                                                  }
                                              }, getWaitInSeconds(response),
                                              TimeUnit.SECONDS);
                break;
            case kXR_close:
                client.getExecutor().schedule(new Runnable() {
                                                  @Override
                                                  public void run() {
                                                      client.doClose(ctx);
                                                  }
                                              }, getWaitInSeconds(response),
                                              TimeUnit.SECONDS);
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
                                                 InboundChecksumResponse response);

    /**
     *  Should implement the proper read logic.  If vector reads are supported,
     *  should direct to special method.
     */
    @Override
    protected abstract void doOnReadResponse(ChannelHandlerContext ctx,
                                             InboundReadResponse response);

    /**
     *  If checksum option is expressed.
     */
    @Override
    protected abstract void sendChecksumRequest(ChannelHandlerContext ctx);

    /**
     *  Should take care of any special handling, such as vectorization.
     */
    @Override
    protected abstract void sendReadRequest(ChannelHandlerContext ctx);
}

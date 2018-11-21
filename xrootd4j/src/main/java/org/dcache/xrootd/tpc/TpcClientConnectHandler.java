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
import org.dcache.xrootd.tpc.protocol.messages.InboundHandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundProtocolResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundLoginRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundProtocolRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>This handler implements protocol and login.</p>
 *
 * <p>If the login response is OK, it hands it off to the next handler
 *    in the chain.</p>
 */
public class TpcClientConnectHandler extends
                AbstractClientRequestHandler
{
    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_login:
                sendLoginRequest(ctx);
                break;
            case kXR_protocol:
                sendProtocolRequest(ctx);
                break;
            default:
                super.doOnAsynResponse(ctx, response);
        }
    }

    @Override
    protected void doOnHandshakeResponse(ChannelHandlerContext ctx,
                                         InboundHandshakeResponse response)
    {
        client.setPval(response.getPval());
        client.setFlag(response.getFlag());
        sendProtocolRequest(ctx);
    }

    @Override
    protected void doOnProtocolResponse(ChannelHandlerContext ctx,
                                        InboundProtocolResponse response)
                    throws XrootdException
    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        if (status == kXR_ok) {
            client.setSeclvl(response.getSeclvl());
            client.setOverrides(response.getOverrides());
            LOGGER.trace("Protocol request to {}, channel {}, stream {},"
                                         + " succeeded, level {}, "
                                         + "overrides {}.",
                         tpcInfo.getSrc(),
                         id,
                         streamId,
                         client.getSeclvl(),
                         client.getOverrides());
            sendLoginRequest(ctx);
        } else {
            String error = String.format(
                            "Protocol request to %s, channel %s, stream %d, "
                                            + "failed: status %d.",
                            tpcInfo.getSrc(),
                            id,
                            streamId,
                            status);
            throw new XrootdException(kXR_error, error);
        }
    }

    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
                    throws XrootdException
    {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        if (status == kXR_ok) {
            client.setSessionId(response.getSessionId());
            LOGGER.trace("Login to {}, channel {}, stream {},"
                                         + " succeeded; sessionId {}; "
                                         + "passing to next handler.",
                         tpcInfo.getSrc(),
                         id,
                         streamId,
                         client.getSessionId());
            ctx.fireChannelRead(response);
        } else {
            String error = String.format("Login to %s, channel %s, stream %d, "
                                                         + "failed: status %d.",
                                         tpcInfo.getSrc(),
                                         id,
                                         streamId,
                                         status);
            throw new XrootdException(kXR_error, error);
        }
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_login:
                client.getExecutor().schedule(() -> {
                    sendLoginRequest(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            case kXR_protocol:
                client.getExecutor().schedule(() -> {
                    sendProtocolRequest(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            default:
                super.doOnWaitResponse(ctx, response);
        }
    }

    @Override
    protected void sendLoginRequest(ChannelHandlerContext ctx)
    {
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.trace("sendLoginRequest to {}, channel {}, stream {}, "
                                     + "pid {}, uname {}.",
                        tpcInfo.getSrc(),
                        ctx.channel().id(),
                        client.getStreamId(),
                        client.getPid(),
                        client.getUname());
        client.setExpectedResponse(kXR_login);
        ctx.writeAndFlush(new OutboundLoginRequest(client.getStreamId(),
                                                   client.getPid(),
                                                   client.getUname(),
                                                   tpcInfo.getLoginToken()),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    protected void sendProtocolRequest(ChannelHandlerContext ctx)
    {
        ChannelId id = ctx.channel().id();
        LOGGER.trace("sendProtocolRequestForClient to {}, channel {}, stream {}.",
                     client.getInfo().getSrc(), id, client.getStreamId());
        client.setExpectedResponse(kXR_protocol);
        ctx.writeAndFlush(new OutboundProtocolRequest(client.getStreamId(),
                                                      PROTOCOL_VERSION),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }
}

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
import io.netty.channel.ChannelId;

import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SecurityInfo;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;

/**
 * <p>Base class for authentication handlers used for outbound requests
 *    from the embedded third-party-client.</p>
 */
public abstract class AbstractClientAuthnHandler extends AbstractClientRequestHandler
{
    protected final String protocol;
    protected InboundLoginResponse loginResponse;

    protected AbstractClientAuthnHandler(String protocol)
    {
        this.protocol = protocol;
    }

    /**
     *  Overridden not to close the client and channel, but
     *  to pass control off to the next (authentication) handler
     *  in the chain.
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable t)
    {
        if (t instanceof RuntimeException) {
            super.exceptionCaught(ctx, t);
            return;
        }

        LOGGER.error("Unable to complete {} authentication to {}, "
                                     + "channel {}, "
                                     + "stream {}, session {}: {}.",
                     protocol,
                     client.getInfo().getSrc(),
                     ctx.channel().id(),
                     client.getStreamId(),
                     client.getSessionId(),
                     t.toString());

        try {
            super.doOnLoginResponse(ctx, loginResponse);
        } catch (XrootdException e) {
            super.exceptionCaught(ctx, e);
        }
    }

    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
                                    InboundAttnResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_auth:
                    sendAuthenticationRequest(ctx);
                break;
            default:
                super.doOnAsynResponse(ctx, response);
        }
    }

    /**
     * Arriving here means login succeeded, but authentication required.
     */
    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
                    throws XrootdException
    {
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        SecurityInfo sec = response.getInfo(protocol);
        if (sec == null) {
            String error = String.format("login to %s, channel %s, stream %s, "
                                                         + "session %s, %s "
                                                         + "handler was added "
                                                         + "to pipeline,"
                                                         + " but the "
                                                         + "protocol was not"
                                                         + "indicated by the "
                                                         + "server; this is "
                                                         + "a bug; please report "
                                                         + "to support@dcache.org.",
                                         tpcInfo.getSrc(),
                                         id,
                                         streamId,
                                         client.getSessionId(),
                                         protocol);
            throw new RuntimeException(error);
        }

        /*
         *  This needs to be stored, in case this protocoal fails and there is
         *  another handler in the pipeline to try.
         */
        loginResponse = response;
        client.setProtocolInfo(sec);
        sendAuthenticationRequest(ctx);
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
                                    AbstractXrootdInboundResponse response)
                    throws XrootdException
    {
        switch (response.getRequestId()) {
            case kXR_auth:
                client.getExecutor().schedule(() -> {
                    try {
                        sendAuthenticationRequest(ctx);
                    } catch (XrootdException e) {
                        exceptionCaught(ctx, e);
                    }
                }, getWaitInSeconds(response), TimeUnit.SECONDS);
                break;
            default:
                super.doOnWaitResponse(ctx, response);
        }
    }
}

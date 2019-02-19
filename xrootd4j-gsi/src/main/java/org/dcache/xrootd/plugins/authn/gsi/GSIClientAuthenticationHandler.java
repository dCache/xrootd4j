/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.pre49.GSIPre49ClientRequestHandler;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 *  <p>Client-side handler mirroring the server-side GSIAuthenticationHandler.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.</p>
 */
public class GSIClientAuthenticationHandler extends AbstractClientAuthnHandler
{
    private GSICredentialManager         credentialManager;
    private GSIClientRequestHandler      requestHandler;
    private InboundLoginResponse         loginResponse;

    public GSIClientAuthenticationHandler(GSICredentialManager credentialManager)
    {
        super(PROTOCOL);
        this.credentialManager = credentialManager;
    }

    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
                                              InboundAuthenticationResponse response)
                    throws XrootdException
    {
        /*
         *  handler will have been constructed on first
         *  sendAuthenticationRequest call
         */
        if (requestHandler.isRequestExpired()) {
            // TODO throw the proper XrootdException
        }

        ChannelId id = ctx.channel().id();
        int status = response.getStatus();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        switch (status) {
            case kXR_ok:
                LOGGER.trace("Authentication to {}, channel {}, stream {}, "
                                             + "sessionId {} succeeded; "
                                             + "passing to next handler.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                ctx.fireChannelRead(response);
                break;
            case kXR_authmore:
                LOGGER.trace("Authentication to {}, channel {}, stream {}, "
                                             + "sessionId {}, "
                                             + "proceeding to next step.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                client.setAuthResponse(response);
                sendAuthenticationRequest(ctx);
                break;
            default:
                throw new XrootdException(kXR_ServerError,
                                          "wrong status from GSI authentication "
                                                          + "response: "
                                                          + status);
        }
    }

    @Override
    protected void sendAuthenticationRequest(ChannelHandlerContext ctx)
                    throws XrootdException
    {
        /*
         *  sendAuthenticationRequest is called by onLoginResponse first,
         *  then by onAuthenticationResponse.
         */
        if (requestHandler == null) {
            /*
             *  REVISIT  check version and create the correct handler
             *           when 49+ protocol added
             */
            requestHandler = new GSIPre49ClientRequestHandler(credentialManager,
                                                              client);
        }

        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        OutboundAuthenticationRequest request;
        InboundAuthenticationResponse previous = client.getAuthResponse();
        if (previous != null) {
            request = requestHandler.handleCertStep(previous, ctx);
            LOGGER.trace("sendAuthenticationRequest to {}, channel {}, "
                                         + "stream {}, step: cert.",
                         tpcInfo.getSrc(), id, streamId);
        } else {
            request = requestHandler.handleCertReqStep();
            LOGGER.trace("sendAuthenticationRequest to {}, channel {}, "
                                         + "stream {}, step: cert request.",
                         tpcInfo.getSrc(), id, streamId);
        }

        requestHandler.updateLastRequest();
        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }
}

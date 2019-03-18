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

import java.util.Optional;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.pre49.GSIPre49ClientRequestHandler;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_WITH_DELEGATION;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrBadOpt;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrBadProtocol;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_cert;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_pxyreq;

/**
 *  <p>Client-side handler mirroring the server-side GSIAuthenticationHandler.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.</p>
 */
public class GSIClientAuthenticationHandler extends AbstractClientAuthnHandler
{
    private GSICredentialManager         credentialManager;
    private GSIClientRequestHandler      requestHandler;
    private int                          serverStep;

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
            throw new XrootdException(kXR_InvalidRequest,
                                      "Authentication request response time expired.");
        }

        serverStep = response.getServerStep();
        ChannelId id = ctx.channel().id();
        int status = response.getStatus();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        switch (status) {
            case kXR_ok:
                LOGGER.debug("Authentication to {}, channel {}, stream {}, "
                                             + "sessionId {} succeeded; "
                                             + "passing to next handler.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                ctx.fireChannelRead(response);
                break;
            case kXR_authmore:
                LOGGER.debug("Authentication to {}, channel {}, stream {}, "
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
         *  then by onAuthenticationResponse.  The request handler
         *  should be created on the login response.
         */
        if (requestHandler == null) {
            requestHandler = createRequestHandler();
        }

        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        OutboundAuthenticationRequest request;
        InboundAuthenticationResponse response = client.getAuthResponse();

        if (response != null) {
            if (!response.getProtocol().equals(PROTOCOL)) {
                throw new XrootdException(kGSErrBadProtocol, "server replied "
                                        + "with incorrect protocol: " +
                                        response.getProtocol());
            }

            switch (serverStep) {
                case kXGS_cert:
                    request = requestHandler.handleCertStep(response, ctx);
                    LOGGER.debug("sendAuthenticationRequest to {}, channel {}, "
                                                 + "stream {}, step: cert.",
                                 tpcInfo.getSrc(), id, streamId);
                    break;
                case kXGS_pxyreq:
                    request = requestHandler.handleSigPxyStep(response, ctx);
                    LOGGER.debug("sendAuthenticationRequest to {}, channel {}, "
                                                 + "stream {}, step: sigpxy.",
                                 tpcInfo.getSrc(), id, streamId);
                    break;
                default:
                    throw new XrootdException(kGSErrBadOpt,
                                              "cannot handle requested" +
                                                              " authentication step "
                                                              + serverStep + ".");
            }
        } else {
            request = requestHandler.handleCertReqStep();
            LOGGER.debug("sendAuthenticationRequest to {}, channel {}, "
                                         + "stream {}, step: cert request.",
                         tpcInfo.getSrc(), id, streamId);
        }

        requestHandler.updateLastRequest();
        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    private GSIClientRequestHandler createRequestHandler()
                    throws XrootdException {
        String serverVersion = ((Optional<String>) client.getAuthnContext()
                                                         .get("version"))
                        .orElse(null);

        if (serverVersion == null) {
            throw new XrootdException(kGSErrBadProtocol,
                                      "Server did not indicate GSI protocol version.");
        }

        int versionToMatch = Integer.parseInt(serverVersion);

        GSIClientRequestHandler handler;

        /*
         *  If the server supports a protocol of 4.9 or later,
         *  use the current.  The server is assumed to be backward
         *  compatible.
         *
         *  Else, use the previous. Once 4.9 is implemented, the previous
         *  only needs to be used when the server is in fact pre-4.9.
         */
        if (versionToMatch >= PROTO_WITH_DELEGATION) {
            /*
             *  REVISIT  bump to 49 version when implemented.
             */
            handler = new GSIPre49ClientRequestHandler(credentialManager,
                                                              client);
        } else {
            handler = new GSIPre49ClientRequestHandler(credentialManager,
                                                              client);
        }

        return handler;
    }
}

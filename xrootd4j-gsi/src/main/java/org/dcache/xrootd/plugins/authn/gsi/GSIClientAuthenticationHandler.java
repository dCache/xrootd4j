/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import java.io.Serializable;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.BucketData;
import org.dcache.xrootd.plugins.authn.gsi.post49.GSIPost49ClientRequestHandler;
import org.dcache.xrootd.plugins.authn.gsi.pre49.GSIPre49ClientRequestHandler;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.plugins.authn.gsi.GSIBucketUtils.deserializeData;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTOCOL;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.PROTO_WITH_DELEGATION;
import static org.dcache.xrootd.plugins.authn.gsi.GSIRequestHandler.VERSION_KEY;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.*;

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

    /*
     *  Override to set the credential store client on the credential manager.
     */
    public void setClient(XrootdTpcClient client)
    {
        super.setClient(client);
    }

    protected void doOnErrorResponse(ChannelHandlerContext ctx,
                                     InboundErrorResponse response)
                    throws XrootdException
    {
        if (requestHandler != null) {
            requestHandler.handleAuthenticationError(response);
        } else {
            XrootdException throwable
                            = new XrootdException(response.getError(),
                                                  response.getErrorMessage());
            exceptionCaught(ctx,
                            new RuntimeException("An authentication error was  "
                                            + "intercepted before an authentication "
                                            + "request was sent; "
                                            + "this is a bug.", throwable));
        }
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
                throw new XrootdException(kGSErrBadOpt,
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
            BucketData data = deserializeData(response);
            serverStep = data.getStep();
            if (!data.getProtocol().equals(PROTOCOL)) {
                throw new XrootdException(kGSErrBadProtocol, "server replied "
                                        + "with incorrect protocol: " +
                                        data.getProtocol());
            }

            switch (serverStep) {
                case kXGS_cert:
                    request = requestHandler.handleCertStep(response, data, ctx);
                    LOGGER.debug("sendAuthenticationRequest to {}, channel {}, "
                                                 + "stream {}, step: cert.",
                                 tpcInfo.getSrc(), id, streamId);
                    break;
                case kXGS_pxyreq:
                    /*
                     *  This is a TPC client only.  It tells the server
                     *  it does not sign proxy requests.  If this
                     *  step is received here, we should reject it.
                     *  Fall through to exception.
                     */
                default:
                    throw new XrootdException(kGSErrBadOpt,
                                              "client does not handle requested " +
                                                              "authentication step "
                                                              + getServerStep(serverStep)
                                                              + ".");
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
        client.startTimer(ctx);
    }

    private GSIClientRequestHandler createRequestHandler()
                    throws XrootdException
    {
        String serverVersion = client.getProtocolInfo().getValue(VERSION_KEY)
                                     .orElse(null);

        if (serverVersion == null) {
            throw new XrootdException(kGSErrBadProtocol,
                                      "Server did not indicate GSI protocol version.");
        }

        int versionToMatch = Integer.parseInt(serverVersion);

        GSIClientRequestHandler handler;

        /*
         *  The reason for this check is not so much to compensate for
         *  a failed attempt to delegate the proxy in the door
         *  (which should fail the transfer), but the following situation:
         *
         *  Suppose the user is authenticating with an XrootD client which
         *  does not support delegation, but the source server tells us it
         *  supports delegation.  The necessary proxy for use by the TPC client
         *  will be missing, and if we match the source implementation
         *  we will fail because of it. So if the proxy is missing, we should
         *  at this point downgrade our version.  The source server should
         *  be backward compatible.
         */
        Serializable proxy = client.getInfo().getDelegatedProxy();

        /*
         *  If the server supports a protocol of 4.9 or later,
         *  and we have a delegated proxy, use the current version.
         *
         *  Else, if allowed, use the previous.
         */
        if (versionToMatch >= PROTO_WITH_DELEGATION && proxy != null) {
            handler = new GSIPost49ClientRequestHandler(credentialManager,
                                                        client);
        } else if (!credentialManager.isDelegationOnly()) {
            handler = new GSIPre49ClientRequestHandler(credentialManager,
                                                       client);
        } else {
            throw new XrootdException(kGSErrError, "proxy delegation required "
                            + "but not available.");
        }

        LOGGER.info("Server protocol version was {}; "
                                    + "delegated proxy exists? {}; using {}.",
                    versionToMatch,
                    proxy != null,
                    handler.getClass().getSimpleName());

        return handler;
    }
}

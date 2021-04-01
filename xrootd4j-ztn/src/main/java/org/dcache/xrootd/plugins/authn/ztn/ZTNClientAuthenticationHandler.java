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
package org.dcache.xrootd.plugins.authn.ztn;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;

import java.util.function.Consumer;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.security.TokenValidator;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.plugins.authn.ztn.ZTNCredential.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 *     Client-side handler which does TPC via ztn authentication.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.
 *     <p/>
 *     This implementation is for future use, since it is not officially
 *     supported for tokens (ztn/scitokens) in xrootd.  It has been tested
 *     works as far as it goes, but how the source token actually arrives
 *     at the TPC client has not yet been resolved.
 *     <p/>
 *     Also, the padding in the token header will be made explicit with
 *     a version of the protocol > 0.  This is necessary for interaction
 *     between xrootd and dCache.
 */
public class ZTNClientAuthenticationHandler extends AbstractClientAuthnHandler
{
    /**
     *  REVISIT.  Version 1 is not yet available, and TPC is not
     *            entirely supported for ztn/scitokens in xrootd
     *            for version 0 of this protocol.
     */
    private static final int  VERSION = 0;
    private static final byte OPR     = (byte)'T';

    public ZTNClientAuthenticationHandler() {
        super(PROTOCOL);
    }

    @Override
    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
                                              InboundAuthenticationResponse response)
                    throws XrootdException
    {
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
            default:
                throw new XrootdException(kXR_error, "failed with status "
                                            + status);
        }
    }

    @Override
    protected void sendAuthenticationRequest(ChannelHandlerContext ctx)
                    throws XrootdException
    {
        LOGGER.warn("TPC with ztn and scitokens is not yet established; "
                                        + "this is not guaranteed to work with "
                                        + "version 0.");

        /*
         *  ZTN requires TLS.  While we can make the reasonable assumption
         *  that the source server will not require signed hash verification,
         *  we check it here anyway just to avoid failure on the off chance
         *  the source is being perverse.
         */
        SigningPolicy signingPolicy = client.getSigningPolicy();
        TLSSessionInfo tlsSessionInfo = client.getTlsSessionInfo();
        if (signingPolicy.isSigningOn()) {
            TpcSigverRequestEncoder sigverRequestEncoder =
                            new TpcSigverRequestEncoder(null, signingPolicy);
            ctx.pipeline().addAfter("encoder",
                                    "sigverEncoder",
                                    sigverRequestEncoder);
            LOGGER.debug("optional signed hash verification encoder has been "
                                         + "added; this is unusual for ZTN:"
                                         + "signing is on? {}; tls ? {}.",
                         signingPolicy.isSigningOn(), tlsSessionInfo.getClientTls());
        }

        /*
         *  REVISIT ---------------------------------------------------
         *
         *  It has yet been established precisely how third-party
         *  token authn/authz is going to work in xrootd.
         *
         *  As a provisional solution to ZTN, we simply assume for the
         *  moment that the source token has somehow been delegated
         *  (e.g., via scgi), and use that for both ZTN and Scitokens
         *  authz.
         */
        String token = client.getInfo().getSourceToken();
        if (token == null) {
            throw new XrootdException(kXR_NotAuthorized,
                                      "TPC was not provided a ztn token.");
        }

        /*
         * The source token is taken from the URL CGI, so it may have a
         * token prefix, which should be stripped off.
         */
        token = TokenValidator.stripOffPrefix(token);
        LOGGER.debug("sendAuthenticationRequest, source token is {}.", token);

        ZTNCredential credential = new ZTNCredential();
        credential.setVersion(VERSION);
        credential.setOpr(OPR);
        credential.setTokenLength(token.length());
        credential.setToken(token);

        Consumer<ByteBuf> serializer = b -> ZTNCredentialUtils.writeBytes(b, credential);
        OutboundAuthenticationRequest request
                        = new OutboundAuthenticationRequest(client.getStreamId(),
                                                            PROTOCOL,
                                                            credential.getLength(),
                                                            serializer);
        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }
}

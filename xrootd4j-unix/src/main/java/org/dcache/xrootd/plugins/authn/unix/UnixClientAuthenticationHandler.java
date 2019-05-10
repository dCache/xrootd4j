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
package org.dcache.xrootd.plugins.authn.unix;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_creds;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_main;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;

/**
 *  <p>Client-side handler which allows TPC via unix authentication.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.</p>
 *
 *  <p>This module is largely in support of authenticating to a dCache
 *     pool, which now requires unix (in order to guarantee signed hashes
 *     are passed from the vanilla xrootd client).</p>
 *
 *  <p>The module merely sends a response with the username; the
 *     sigver handler is given no crypto handler, and thus sigver requests
 *     will be signed without encryption.</p>
 */
public class UnixClientAuthenticationHandler extends AbstractClientAuthnHandler
{
    public static final String PROTOCOL = "unix";

    public UnixClientAuthenticationHandler() {
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
                LOGGER.trace("Authentication to {}, channel {}, stream {}, "
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
    {
        /*
         * Insert sigver encoder into pipeline.  Added after the encoder,
         * but for outbound processing, it gets called before the encoder.
         */
        TpcSigverRequestEncoder sigverRequestEncoder =
                        new TpcSigverRequestEncoder(null,
                                                    client.getSigningPolicy());
        ctx.pipeline().addAfter("encoder",
                                "sigverEncoder",
                                sigverRequestEncoder);

        Map<BucketType, XrootdBucket> nestedBuckets
                        = new EnumMap<>(BucketType.class);
        StringBucket unameBucket = new StringBucket(kXRS_creds, client.getUname());
        nestedBuckets.put(unameBucket.getType(), unameBucket);
        NestedBucketBuffer mainBucket = new NestedBucketBuffer(kXRS_main,
                                                               PROTOCOL,
                                                               kXGC_cert,
                                                               nestedBuckets);
        OutboundAuthenticationRequest request
                        = new OutboundAuthenticationRequest(client.getStreamId(),
                                                            mainBucket.getSize(),
                                                            PROTOCOL,
                                                            kXGC_cert,
                                                            Collections.singletonList(mainBucket));
        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }
}

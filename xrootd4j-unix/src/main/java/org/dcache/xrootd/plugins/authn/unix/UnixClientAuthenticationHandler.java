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
package org.dcache.xrootd.plugins.authn.unix;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.channel.ChannelInboundHandler;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.NestedBucketBuffer;
import org.dcache.xrootd.security.StringBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.dcache.xrootd.tpc.AbstractClientRequestHandler;
import org.dcache.xrootd.tpc.TpcSigverRequestHandler;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
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
public class UnixClientAuthenticationHandler extends
                AbstractClientRequestHandler implements ChannelInboundHandler
{
    public static final String PROTOCOL = "unix";

    /**
     * Arriving here means login succeeded.  Check for authentication
     * requirement.
     */
    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                     InboundLoginResponse response)
    {
        ChannelId id = ctx.channel().id();
        String sec = response.getSec();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();

        if (sec == null) {
            LOGGER.trace("login to {}, channel {}, stream {}, session {}, "
                                         + "does not require "
                                         + "authentication; "
                                         + "passing to next handler in chain.",
                         tpcInfo.getSrc(),
                         id,
                         streamId,
                         client.getSessionId());
            ctx.fireChannelRead(response);
            return;
        }

        try {
            if (!isUnixRequred(sec)) {
                LOGGER.trace("login to {}, channel {}, stream {}, session {}, "
                                             + "requires a different protocol; "
                                             + "passing to next handler in chain.",
                             tpcInfo.getSrc(),
                             id,
                             streamId,
                             client.getSessionId());
                ctx.fireChannelRead(response);
                return;
            }

            sendAuthenticationRequest(ctx);
        } catch (XrootdException e) {
            exceptionCaught(ctx, e);
        }
    }

    @Override
    protected void sendAuthenticationRequest(ChannelHandlerContext ctx)
    {
        TpcSigverRequestHandler sigverRequestHandler =
                        new TpcSigverRequestHandler(null, client);
        client.setSigverRequestHandler(sigverRequestHandler);
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
    }

    private boolean isUnixRequred(String sec) throws XrootdException
    {
        if (!sec.startsWith("&P=")) {
            throw new XrootdException(kXR_error, "Malformed 'sec': " + sec);
        }
        int comma = sec.indexOf(",");
        String protocol = comma > 3 ? sec.substring(3, comma) : sec.substring(3, 7);
        LOGGER.trace("checking for unix; protocol is {}", protocol);
        return PROTOCOL.equals(protocol.trim());
    }
}

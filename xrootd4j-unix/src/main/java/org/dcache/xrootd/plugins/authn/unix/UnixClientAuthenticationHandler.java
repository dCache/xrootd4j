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
package org.dcache.xrootd.plugins.authn.unix;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.core.XrootdEncoder.writeZeroPad;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_error;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.protocol.messages.LoginResponse.AUTHN_PROTOCOL_TYPE_LEN;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_creds;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_main;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_none;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_cert;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import java.util.function.Consumer;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SigningPolicy;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.tpc.AbstractClientAuthnHandler;
import org.dcache.xrootd.tpc.TpcSigverRequestEncoder;
import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.XrootdTpcInfo;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;

/**
 *  <p>Client-side handler which allows TPC via unix authentication.
 *     Added to the channel pipeline to handle protocol and auth requests
 *     and responses.</p>
 *
 *  <p>This module is largely in support of authenticating to a dCache
 *     pool, which now requires unix (in order to guarantee signed hashes
 *     are passed from the vanilla xrootd client).</p>
 *
 *  The module merely sends a response with the username; the
 *     sigver handler is given no crypto handler, and thus sigver requests
 *     will be signed without encryption.</p>
 */
public class UnixClientAuthenticationHandler extends AbstractClientAuthnHandler {

    public static final String PROTOCOL = "unix";

    private static String getCredential(XrootdTpcClient client) {
        return client.getUname();
    }

    /*
     *  The correct structure of the unix request is as follows:
     *
     *  Outbound =  4 + [16 + 4] + data [40 + len]
     *
     *  streamId	2
     *  kXR_auth    2
     *
     *  \0		    16
     *  data len	4	= 12[*] + buffer length
     *
     *  protocol	4*
     *  step		4*
     *  =========
     *  code		4	kXRS_main_code
     *  len		    4	= 12[†] + 4 + 4 + len
     *  protocol	4†
     *  step		4†
     *  ---------
     *  code	    4	kXRS_creds_code
     *  len	        4
     *  cred	    len
     *  code	    4†	kXRS_none
     *  =========
     *  code		4*	kXRS_none
     */
    private static void writeBytes(ByteBuf buffer, String cred) {
        byte[] bytes = cred.getBytes(US_ASCII);
        writeZeroPad(PROTOCOL, buffer, AUTHN_PROTOCOL_TYPE_LEN);
        buffer.writeInt(kXGC_cert);
        buffer.writeInt(kXRS_main.getCode());
        buffer.writeInt(getBufferLength(bytes.length));
        writeZeroPad(PROTOCOL, buffer, AUTHN_PROTOCOL_TYPE_LEN);
        buffer.writeInt(kXGC_cert);
        buffer.writeInt(kXRS_creds.getCode());
        buffer.writeInt(bytes.length);
        buffer.writeBytes(bytes);
        buffer.writeInt(kXRS_none.getCode());
        buffer.writeInt(kXRS_none.getCode());
    }

    private static int getBufferLength(int credlen) {
        return 28 + credlen;
    }

    private static int getCredentialLength(String cred) {
        return 12 + getBufferLength(cred.getBytes(US_ASCII).length);
    }

    public UnixClientAuthenticationHandler() {
        super(PROTOCOL);
    }

    @Override
    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
          InboundAuthenticationResponse response)
          throws XrootdException {
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
    protected void sendAuthenticationRequest(ChannelHandlerContext ctx) {
        SigningPolicy signingPolicy = client.getSigningPolicy();
        TLSSessionInfo tlsSessionInfo = client.getTlsSessionInfo();
        LOGGER.debug("Getting (optional) signed hash verification encoder, "
                    + "signing is on? {}; tls ? {}.",
              signingPolicy.isSigningOn(), tlsSessionInfo.getClientTls());
        if (signingPolicy.isSigningOn()) {
            /*
             * Insert sigver encoder into pipeline.  Added after the encoder,
             * but for outbound processing, it gets called before the encoder.
             */
            TpcSigverRequestEncoder sigverRequestEncoder =
                  new TpcSigverRequestEncoder(null, signingPolicy);
            ctx.pipeline().addAfter("encoder",
                  "sigverEncoder",
                  sigverRequestEncoder);
        }

        String cred = getCredential(client);
        Consumer<ByteBuf> serializer = b -> writeBytes(b, cred);
        OutboundAuthenticationRequest request
              = new OutboundAuthenticationRequest(client.getStreamId(),
              "",
              getCredentialLength(cred),
              serializer);
        client.setExpectedResponse(kXR_auth);
        client.setAuthResponse(null);
        ctx.writeAndFlush(request, ctx.newPromise())
              .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }
}

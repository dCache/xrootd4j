/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.tpc;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.channel.ChannelPipeline;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SecurityInfo;
import org.dcache.xrootd.security.TLSSessionInfo;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundHandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundProtocolResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundLoginRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundProtocolRequest;

/**
 * This handler implements protocol and login.</p>
 *
 * If the login response is OK, it hands it off to the next handler
 *    in the chain.</p>
 */
public class TpcClientConnectHandler extends
      AbstractClientRequestHandler {

    @Override
    protected void doOnAsynResponse(ChannelHandlerContext ctx,
          InboundAttnResponse response)
          throws XrootdException {
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
          InboundHandshakeResponse response) {
        client.setPval(response.getPval());
        client.setFlag(response.getFlag());
        sendProtocolRequest(ctx);
    }

    @Override
    protected void doOnProtocolResponse(ChannelHandlerContext ctx,
          InboundProtocolResponse response)
          throws XrootdException {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        TLSSessionInfo tlsSessionInfo = client.getTlsSessionInfo();
        tlsSessionInfo.setSourceServerFlags(response.getFlags());
        LOGGER.debug("Protocol response on {}, channel {}, stream {},"
                    + " received, signing policy {}; tls {}; status {}.",
              tpcInfo.getSrc(),
              id,
              streamId,
              response.getSigningPolicy(),
              tlsSessionInfo.getClientTls(),
              status);
        if (status == kXR_ok) {
            client.setSigningPolicy(response.getSigningPolicy());
            LOGGER.debug("Protocol request to {}, channel {}, stream {},"
                        + " succeeded; sending login request.",
                  tpcInfo.getSrc(),
                  id,
                  streamId);
            sendLoginRequest(ctx);
        } else {
            String error = String.format(
                  "Protocol request to %s failed with status %d.",
                  tpcInfo.getSrc(),
                  status);
            throw new XrootdException(kXR_InvalidRequest, error);
        }
    }

    @Override
    protected void doOnLoginResponse(ChannelHandlerContext ctx,
          InboundLoginResponse response)
          throws XrootdException {
        int status = response.getStatus();
        ChannelId id = ctx.channel().id();
        int streamId = client.getStreamId();
        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("Login response on {}, channel {}, stream {},"
                    + " received; sessionId {}, status {}.",
              tpcInfo.getSrc(),
              id,
              streamId,
              response.getSessionId(),
              status);

        if (status == kXR_ok) {
            client.setSessionId(response.getSessionId());

            List<SecurityInfo> protocols = response.getProtocols();
            Map<String, ChannelHandler> handlers = client.getAuthnHandlers();

            /*
             *  Name of this handler
             */
            String last = "connect";
            ChannelPipeline pipeline = ctx.pipeline();
            for (SecurityInfo protocol : protocols) {
                String name = protocol.getProtocol();
                ChannelHandler handler = handlers.get(name);
                if (handler != null) {
                    pipeline.addAfter(last, name, handler);
                    last = name;

                    LOGGER.debug("Login to {}, channel {}, stream {}, sessionId {}, "
                                + "adding {} handler to pipeline.",
                          tpcInfo.getSrc(),
                          id,
                          streamId,
                          client.getSessionId(),
                          name);
                }
            }

            LOGGER.debug("Login to {}, channel {}, stream {},"
                        + " succeeded; sessionId {}; "
                        + "passing to next handler.",
                  tpcInfo.getSrc(),
                  id,
                  streamId,
                  client.getSessionId());

            ctx.fireChannelRead(response);
        } else {
            String error = String.format("Login to %s failed: status %d.",
                  tpcInfo.getSrc(),
                  status);
            throw new XrootdException(kXR_InvalidRequest, error);
        }
    }

    @Override
    protected void doOnWaitResponse(final ChannelHandlerContext ctx,
          AbstractXrootdInboundResponse response)
          throws XrootdException {
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
    protected void sendLoginRequest(ChannelHandlerContext ctx) {
        TLSSessionInfo tlsSessionInfo = client.getTlsSessionInfo();
        try {
            boolean isStarted = tlsSessionInfo.clientTransitionedToTLS(kXR_login,
                  ctx);
            LOGGER.debug("kXR_login, transitioning client to TLS? {}.",
                  isStarted);
        } catch (XrootdException e) {
            exceptionCaught(ctx, e);
            return;
        }

        XrootdTpcInfo tpcInfo = client.getInfo();
        LOGGER.debug("sendLoginRequest to {}, channel {}, stream {}, "
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
        client.startTimer(ctx);
    }

    protected void sendProtocolRequest(ChannelHandlerContext ctx) {
        ChannelId id = ctx.channel().id();
        LOGGER.debug("sendProtocolRequestForClient to {}, channel {}, stream {}.",
              client.getInfo().getSrc(), id, client.getStreamId());
        client.setExpectedResponse(kXR_protocol);
        int[] flags = client.getTlsSessionInfo().getClientFlags();
        ctx.writeAndFlush(new OutboundProtocolRequest(client.getStreamId(),
                          flags[0],
                          flags[1],
                          flags[2]),
                    ctx.newPromise())
              .addListener(FIRE_EXCEPTION_ON_FAILURE);
        client.startTimer(ctx);
    }
}

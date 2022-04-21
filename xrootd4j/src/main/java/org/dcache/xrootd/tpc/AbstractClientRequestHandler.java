/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgInvalid;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_InvalidRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Unsupported;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncab;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncav;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncdi;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncgo;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncms;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncrd;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncwt;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asynresp;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asynunav;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_close;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_handshake;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_noResponsesYet;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_read;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelId;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.TimeUnit;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.tpc.protocol.messages.AbstractXrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAttnResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundChecksumResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundCloseResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundErrorResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundHandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundOpenReadOnlyResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundProtocolResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundRedirectResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitRespResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundAuthenticationRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundChecksumRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundCloseRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundLoginRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundOpenReadOnlyRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundReadRequest;
import org.dcache.xrootd.tpc.protocol.messages.XrootdInboundResponse;
import org.dcache.xrootd.tpc.protocol.messages.XrootdOutboundRequest;
import org.dcache.xrootd.util.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This handler is intended for implementation of only a very limited
 *    subset of the protocol in order to support third-party read requests.
 *    It exposes the handshake, login, protocol, auth, open, read, close
 *    and endsession exchanges.</p>
 */
public abstract class AbstractClientRequestHandler extends
      ChannelInboundHandlerAdapter {

    protected static final Logger LOGGER
          = LoggerFactory.getLogger(AbstractClientRequestHandler.class);

    protected XrootdTpcClient client;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof XrootdInboundResponse) {
            client.stopTimer();
            responseReceived(ctx, (XrootdInboundResponse) msg);
            return;
        }
        ctx.fireChannelRead(msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
        if (t instanceof ClosedChannelException) {
            LOGGER.warn("ClosedChannelException caught on channel {}.",
                  ctx.channel().id());
        } else if (t instanceof IOException) {
            LOGGER.error("IOException caught on channel {}: {}.",
                  ctx.channel().id(), t.toString());
        } else if (t instanceof XrootdException) {
            LOGGER.error("Exception caught on channel {}: {}.",
                  ctx.channel().id(),
                  t.toString());
        } else {
            LOGGER.error("Exception caught on channel {}: {}",
                  ctx.channel().id(),
                  t.getMessage());
            Thread me = Thread.currentThread();
            me.getUncaughtExceptionHandler().uncaughtException(me, t);
        }

        if (client != null) {
            client.setError(t);
            client.shutDown(ctx);
        }
    }

    public void setClient(XrootdTpcClient client) {
        this.client = client;
    }

    protected void asynWaitTimeout(ChannelHandlerContext ctx,
          InboundWaitRespResponse response) {
        String message = String.format("waited %d secs for server attn, "
                    + "never received response.",
              getWaitInSeconds(response));

        LOGGER.error("Channel {}: {}.", ctx.channel().id(), message);

        if (client != null) {
            client.setError(new XrootdException(kXR_noResponsesYet, message));
            client.shutDown(ctx);
        }

    }

    protected void doOnAsynResponse(ChannelHandlerContext ctx,
          InboundAttnResponse response)
          throws XrootdException {
        switch (response.getRequestId()) {
            case kXR_endsess:
                client.doEndsession(ctx);
                break;
            default:
                ctx.fireChannelRead(response);
        }
    }

    protected void doOnAuthenticationResponse(ChannelHandlerContext ctx,
          InboundAuthenticationResponse response)
          throws XrootdException {
        LOGGER.debug("doOnAuthenticationResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnChecksumResponse(ChannelHandlerContext ctx,
          InboundChecksumResponse response)
          throws XrootdException {
        LOGGER.debug("doOnChecksumResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnCloseResponse(ChannelHandlerContext ctx,
          InboundCloseResponse response)
          throws XrootdException {
        LOGGER.debug("doOnCloseResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnErrorResponse(ChannelHandlerContext ctx,
          InboundErrorResponse response)
          throws XrootdException {
        throw new XrootdException(response.getError(),
              response.getErrorMessage());
    }

    protected void doOnHandshakeResponse(ChannelHandlerContext ctx,
          InboundHandshakeResponse response)
          throws XrootdException {
        LOGGER.debug("doOnHandshakeResponse, channel {}"
                    + " –– passing to next in chain.",
              ctx.channel().id());
        ctx.fireChannelRead(response);
    }

    protected void doOnLoginResponse(ChannelHandlerContext ctx,
          InboundLoginResponse response)
          throws XrootdException {
        LOGGER.debug("doOnLoginResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnOpenResponse(ChannelHandlerContext ctx,
          InboundOpenReadOnlyResponse response)
          throws XrootdException {
        LOGGER.debug("doOnOpenResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnProtocolResponse(ChannelHandlerContext ctx,
          InboundProtocolResponse response)
          throws XrootdException {
        LOGGER.debug("doOnProtocolResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnReadResponse(ChannelHandlerContext ctx,
          InboundReadResponse response)
          throws XrootdException {
        LOGGER.debug("doOnReadResponse, channel {}, stream {}"
                    + " –– passing to next in chain.",
              ctx.channel().id(), response.getStreamId());
        ctx.fireChannelRead(response);
    }

    protected void doOnRedirectResponse(ChannelHandlerContext ctx,
          InboundRedirectResponse response)
          throws XrootdException {
        ChannelId id = ctx.channel().id();
        LOGGER.debug("redirecting client from {} to {}:{}, channel {}, "
                    + "stream {}; [info {}].",
              client.getInfo().getSrc(),
              response.getHost(),
              response.getPort(),
              id, client.getStreamId(),
              client.getInfo());
        client.getWriteHandler().redirect(ctx, response);
    }

    protected void doOnAttnResponse(ChannelHandlerContext ctx,
          InboundAttnResponse response)
          throws XrootdException {
        String message;

        switch (response.getActnum()) {
            case kXR_asyncab:
                /*
                 * The client should immediately disconnect (i.e., close
                 * the socket connection) from the server and abort
                 * further execution.
                 */
                message = "Received abort from source server: "
                      + response.getMessage();
                throw new XrootdException(kXR_ServerError, message);
            case kXR_asyncms:
                /*
                 * The client should send the indicated message to the console.
                 * The parameters contain the message text.
                 */
                LOGGER.info("Received from source server: {}.",
                      response.getMessage());
                break;
            case kXR_asyncgo:
                /*
                 * The client may start sending requests. This code is sent to
                 * cancel the effects of a previous kXR_asyncwt code.
                 *
                 * Fall through to handle future cancellation.
                 */
            case kXR_asynresp:
                /*
                 * The client should use the response data in the message to
                 * complete the request associated with the indicated streamid.
                 *
                 * For this to be valid, there has to be a waiting request
                 * for this pipeline.  If future is null here, we skip it.
                 */
                if (client.cancelAttnFuture()) {
                    doOnAsynResponse(ctx, response);
                }
                break;
            case kXR_asyncwt:
                /*
                 * The client should hold off sending any new requests until the
                 * indicated amount of time has passed or until receiving a
                 * kXR_asyncgo action code.
                 */
                doOnWaitResponse(ctx, response);
                break;
            case kXR_asyncrd:
                /*
                 * The client should immediately disconnect (i.e., close the
                 * socket connection) and reconnect to the indicated server.
                 *
                 * NOTE:  without opaque data in the parameters, this redirect
                 * probably will not work here, but we will allow this to fail
                 * downstream.
                 *
                 * Fall through to redirect.
                 */
            case kXR_asyncdi:
                /*
                 * The client should immediately disconnect
                 * (i.e., close the socket connection) from the server.
                 * Parameters indicate when a reconnect may be attempted.
                 *
                 * This is essentially a delayed redirect to the same
                 * endpoint.
                 */
                try {
                    doOnRedirectResponse(ctx,
                          new InboundRedirectResponse(response));
                } catch (ParseException e) {
                    throw new XrootdException(kXR_InvalidRequest,
                          "bad redirect data from kXR_asyncdi");
                }
                break;
            case kXR_asyncav:
                /*
                 * The file or file(s) the client previously
                 * requested to be prepared are now available.
                 *
                 * We do not issue prepare requests.  NR.
                 */
            case kXR_asynunav:
                /*
                 * The file or file(s) the client previously requested to
                 * be prepared cannot be made available.
                 *
                 * We do not issue prepare requests.  NR.
                 */
                throw new XrootdException(kXR_Unsupported,
                      "tpc client does not support this option: "
                            + response.getActnum());
            default:
                throw new XrootdException(kXR_ArgInvalid,
                      "unrecognized kXR_attn action: "
                            + response.getActnum());
        }
    }

    /*
     * Do not wait on the event thread.
     *
     * Incoming here is either an InboundWaitResponse or an InboundAttnResponse
     * of the type kXR_asyncwt.  Cancelled by kXR_ayncgo.
     */
    protected synchronized void doOnWaitResponse(final ChannelHandlerContext ctx,
          AbstractXrootdInboundResponse response)
          throws XrootdException {
        switch (response.getRequestId()) {
            case kXR_endsess:
                client.setAttnFuture(client.getExecutor().schedule(() -> {
                    client.doEndsession(ctx);
                }, getWaitInSeconds(response), TimeUnit.SECONDS));
                break;
            default:
                ctx.fireChannelRead(response);
        }
    }

    /*
     * Do not wait on the event thread.
     *
     * If the future is not cancelled, it must throw a timeout exception/failure.
     * Cancelled by kXR_asynresp.
     */
    protected synchronized void doOnWaitRespResponse(final ChannelHandlerContext ctx,
          InboundWaitRespResponse response)
          throws XrootdException {
        client.setAttnFuture(client.getExecutor().schedule(() -> {
            asynWaitTimeout(ctx, response);
        }, getWaitInSeconds(response), TimeUnit.SECONDS));
    }

    protected int getWaitInSeconds(AbstractXrootdInboundResponse response) {
        int wsec = 0;
        int msec = 0;
        if (response instanceof InboundWaitResponse) {
            msec = ((InboundWaitResponse) response).getMaxWaitInSeconds();
            wsec = 10;
        } else if (response instanceof InboundWaitRespResponse) {
            msec = ((InboundWaitRespResponse) response).getMaxWaitInSeconds();
            wsec = msec;
        } else if (response instanceof InboundAttnResponse) {
            InboundAttnResponse attnResponse = (InboundAttnResponse) response;
            wsec = attnResponse.getWsec();
            msec = wsec;
        }
        return Math.min(wsec, msec);
    }

    protected void responseReceived(ChannelHandlerContext ctx,
          XrootdInboundResponse response) {
        try {
            if (response instanceof InboundWaitResponse) {
                doOnWaitResponse(ctx, (InboundWaitResponse) response);
                return;
            }

            if (response instanceof InboundWaitRespResponse) {
                doOnWaitRespResponse(ctx, (InboundWaitRespResponse) response);
                return;
            }

            if (response instanceof InboundErrorResponse) {
                doOnErrorResponse(ctx, (InboundErrorResponse) response);
                return;
            }

            if (response instanceof InboundRedirectResponse) {
                doOnRedirectResponse(ctx, (InboundRedirectResponse) response);
                return;
            }

            if (response instanceof InboundAttnResponse) {
                doOnAttnResponse(ctx, (InboundAttnResponse) response);
                return;
            }

            int streamId = response.getStreamId();
            ChannelId id = ctx.channel().id();
            int requestId = response.getRequestId();

            switch (requestId) {
                case kXR_auth:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_auth.",
                          id, streamId);
                    doOnAuthenticationResponse(ctx,
                          (InboundAuthenticationResponse) response);
                    break;
                case kXR_close:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_close.",
                          id, streamId);
                    doOnCloseResponse(ctx, (InboundCloseResponse) response);
                    break;
                case kXR_endsess:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_endsess.",
                          id, streamId);
                    LOGGER.debug("endsession response received.");
                    client.disconnect(); // will not attempt disconnect twice
                    break;
                case kXR_handshake:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_handshake.",
                          id, streamId);
                    doOnHandshakeResponse(ctx,
                          (InboundHandshakeResponse) response);
                    break;
                case kXR_login:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_login.",
                          id, streamId);
                    doOnLoginResponse(ctx, (InboundLoginResponse) response);
                    break;
                case kXR_open:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_open.",
                          id, streamId);
                    doOnOpenResponse(ctx,
                          (InboundOpenReadOnlyResponse) response);
                    break;
                case kXR_protocol:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_protocol.",
                          id, streamId);
                    doOnProtocolResponse(ctx,
                          (InboundProtocolResponse) response);
                    break;
                case kXR_query:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_query.",
                          id, streamId);
                    doOnChecksumResponse(ctx,
                          (InboundChecksumResponse) response);
                    break;
                case kXR_read:
                    LOGGER.debug("responseReceived, channel {}, stream {}, "
                                + "requestId = kXR_read.",
                          id, streamId);
                    doOnReadResponse(ctx, (InboundReadResponse) response);
                    break;
                default:
                    String error = String.format(
                          "Response (channel %s, stream %d, "
                                + "request %s) "
                                + "should not have "
                                + "been received "
                                + "by tpc client; "
                                + "this is a bug;"
                                + "please report to "
                                + "support@dcache.org.",
                          id, streamId, requestId);
                    throw new RuntimeException(error);
            }
        } catch (Throwable t) {
            exceptionCaught(ctx, t);
        }
    }

    protected void sendAuthenticationRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundAuthenticationRequest.class);
    }

    protected void sendChecksumRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundChecksumRequest.class);
    }

    protected void sendCloseRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundCloseRequest.class);
    }

    protected void sendLoginRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundLoginRequest.class);
    }

    protected void sendOpenRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundOpenReadOnlyRequest.class);
    }

    protected void sendReadRequest(ChannelHandlerContext ctx)
          throws XrootdException {
        unsupported(OutboundReadRequest.class);
    }

    protected <T extends XrootdOutboundRequest> void unsupported(Class<T> msg)
          throws XrootdException {
        LOGGER.warn("Unsupported request: " + msg.getSimpleName());
        throw new XrootdException(kXR_Unsupported, "request "
              + msg.getSimpleName() + " not supported");
    }
}

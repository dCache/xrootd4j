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
package org.dcache.xrootd.tpc;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.channels.ClosedChannelException;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.core.XrootdSessionIdentifier;
import org.dcache.xrootd.tpc.core.XrootdClientDecoder;
import org.dcache.xrootd.tpc.protocol.messages.HandshakeRequest;
import org.dcache.xrootd.tpc.protocol.messages.HandshakeResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundAuthenticationResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundCloseResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundEndSessionResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundLoginResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundOpenReadOnlyResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundReadResponse;
import org.dcache.xrootd.tpc.protocol.messages.InboundWaitResponse;
import org.dcache.xrootd.tpc.protocol.messages.OutboundCloseRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundEndSessionRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundLoginRequest;
import org.dcache.xrootd.tpc.protocol.messages.OutboundOpenReadOnlyRequest;
import org.dcache.xrootd.tpc.protocol.messages.XrootdInboundResponse;
import org.dcache.xrootd.util.OpaqueStringParser;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>Xrootd Third Party copy requires the destination server to be active,
 *    and request a read of the source file from the source server.</p>
 *
 * <p>This handler is intended for implementation of only a very limited
 *    subset of the protocol in order to support third-party read requests.
 *    It exposes the handshake, login, open, read, close and endsession
 *    interactions.</p>
 *
 * <p>It assumes that the XrootdClientDecoder is bound to one request stream
 *    at a time.</p>
 *
 * <p>Implementations must handle the actual read requests and responses,
 *    and determine what to do when the client closes and
 *    disconnects from the server.</p>
 */
public abstract class AbstractTpcClientRequestHandler extends
                ChannelInboundHandlerAdapter
{
    protected static final Logger LOGGER
                    = LoggerFactory.getLogger(AbstractTpcClientRequestHandler.class);

    protected final XrootdClientDecoder decoder;

    protected final XrootdTpcInfo tpcInfo;
    protected final int    pid;
    protected final String uname;
    protected final String fullpath;
    protected final int    streamId;

    protected XrootdSessionIdentifier sessionId;
    protected int                     fhandle;

    protected int    pval;
    protected int    flag;
    protected String sec;
    protected int    cpsize;
    protected int    cptype;

    protected long writeOffset;

    protected boolean isOpenFile;
    protected boolean isRunning;

    AbstractTpcClientRequestHandler(XrootdTpcInfo info,
                                    String xrdclient,
                                    int streamId)
    {
        this.tpcInfo = info;
        this.streamId = streamId;

        String user = xrdclient.split("@")[0];
        String[] userSplit = user.split("[.]");
        uname = System.getProperty("user.name");
        pid = Integer.parseInt(userSplit[1]);

        fullpath = info.getLfn()
                        + OpaqueStringParser.OPAQUE_STRING_PREFIX
                        + XrootdTpcInfo.RENDEZVOUS_KEY
                        + OpaqueStringParser.OPAQUE_SEPARATOR
                        + info.getKey()
                        + OpaqueStringParser.OPAQUE_PREFIX
                        + XrootdTpcInfo.CLIENT
                        + OpaqueStringParser.OPAQUE_SEPARATOR
                        + xrdclient;

        writeOffset = 0L;

        decoder = new XrootdClientDecoder();

        isRunning = true;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx)
    {
        sendHandshakeRequest(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg)
    {
        if (msg instanceof XrootdInboundResponse) {
            responseReceived(ctx, (XrootdInboundResponse) msg);
            return;
        }
        ctx.write(msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable t)
    {
        if (t instanceof ClosedChannelException) {
            LOGGER.trace("Connection {} unexpectedly closed.", ctx.channel());
        } else if (t instanceof Exception) {
            LOGGER.error("Exception caught {}.", t.toString());
        } else {
            Thread me = Thread.currentThread();
            me.getUncaughtExceptionHandler().uncaughtException(me, t);
        }

        handleServerDisconnect(ctx, null);
    }

    @Override
    public String toString()
    {
        return new StringBuilder(tpcInfo.toString())
                        .append("(uname ").append(uname)
                        .append(")(pid ").append(pid)
                        .append(")(fullpath ").append(fullpath)
                        .append(")(streamId ").append(streamId)
                        .append(")(sessionId ").append(sessionId)
                        .append(")(fhandle ").append(fhandle)
                        .append(")(pval ").append(pval)
                        .append(")(sec ").append(sec)
                        .append(")(cpsize ").append(cpsize)
                        .append(")(cptype ").append(cptype).append(")")
                        .toString();
    }

    protected void doOnCloseResponse(ChannelHandlerContext ctx,
                                   InboundCloseResponse response)
    {
        int status = response.getStatus();
        if (status == kXR_ok) {
            LOGGER.trace("Close of {} on {}:{} succeeded.",
                         tpcInfo.getLfn(), tpcInfo.getSrc(),
                         tpcInfo.getSrcPort());
        } else {
            LOGGER.warn("Close of {} on {}:{} failed: status {}.",
                        tpcInfo.getLfn(), tpcInfo.getSrc(),
                        tpcInfo.getSrcPort(), status);
        }
        isOpenFile = false;
        handleServerDisconnect(ctx, null);
    }

    protected void doOnEndSessionResponse(ChannelHandlerContext ctx,
                                        InboundEndSessionResponse response)
    {
        int status = response.getStatus();
        if (status == kXR_ok) {
            LOGGER.trace("End session {} on {}:{} succeeded.",
                         sec, tpcInfo.getLfn(), tpcInfo.getSrc());
        } else {
            LOGGER.warn("End session {} on {}:{} failed: status {}.",
                        sec, tpcInfo.getLfn(), tpcInfo.getSrc(), status);
        }
        sessionId = null;
        handleServerDisconnect(ctx, null);
    }

    protected void doOnHandshakeResponse(ChannelHandlerContext ctx,
                                       HandshakeResponse response)
    {
        int status = response.getStatus();
        if (status == kXR_ok) {
            pval = response.getPval();
            flag = response.getFlag();
            LOGGER.trace("Handshake with {}:{} succeeded, version {}, "
                                         + "server type {}.",
                         tpcInfo.getLfn(), tpcInfo.getSrc(), pval, flag);
            sendLoginRequest(ctx);
        } else {
            String error = String.format(
                            "Handshake with %s:%s failed: status %d.",
                            tpcInfo.getLfn(), tpcInfo.getSrc(), status);
            handleServerDisconnect(ctx, error);
        }
    }

    protected void doOnLoginResponse(ChannelHandlerContext ctx,
                                   InboundLoginResponse response)
    {
        int status = response.getStatus();
        if (status == kXR_ok) {
            sessionId = response.getSessionId();
            sec = response.getSec();
            LOGGER.trace("Login to {}:{} succeeded, sec {}.",
                         tpcInfo.getLfn(), tpcInfo.getSrc(), sec);

            if (sec != null) {
                sendAuthenticationRequest(ctx);
            } else {
                sendOpenRequest(ctx);
            }
        } else {
            String error = String.format("Login to %s:%s failed: status %d.",
                                         tpcInfo.getLfn(), tpcInfo.getSrc(),
                                         status);
            handleServerDisconnect(ctx, error);
        }
    }

    protected void doOnOpenResponse(ChannelHandlerContext ctx,
                                  InboundOpenReadOnlyResponse response)
    {
        int status = response.getStatus();
        if (status == kXR_ok) {
            isOpenFile = true;
            fhandle = response.getFhandle();
            cpsize = response.getCpsize();
            cptype = response.getCptype();
            LOGGER.trace("Open of {} on {}:{} succeeded, "
                                         + "fhandle {}, cpsize {}, cptype {}.",
                         tpcInfo.getLfn(), tpcInfo.getSrc(),
                         tpcInfo.getSrcPort(),
                         fhandle, cpsize, cptype);
            sendReadRequest(ctx);
        } else {
            String error = String.format(
                            "Open of %s on %s:%s failed: status %d.",
                            tpcInfo.getLfn(), tpcInfo.getSrc(),
                            tpcInfo.getSrcPort(), status);
            handleServerDisconnect(ctx, error);
        }
    }

    protected void doOnWaitResponse(ChannelHandlerContext ctx,
                                    InboundWaitResponse response)
    {
        long secs = Math.min(10, response.getMaxWaitInSeconds());
        try {
            LOGGER.info("waiting {} seconds.", secs);
            TimeUnit.SECONDS.sleep(secs);
        } catch (InterruptedException e) {
            LOGGER.warn("wait for server, interrupted.");
        }

        int requestId = response.getRequestId();
        switch (requestId) {
            case kXR_handshake:
                LOGGER.trace("retrying kXR_handshake after wait of {} seconds.", secs);
                sendHandshakeRequest(ctx);
                break;
            case kXR_auth:
                LOGGER.trace("retrying kXR_auth after wait of {} seconds.", secs);
                sendAuthenticationRequest(ctx);
                break;
            case kXR_login:
                LOGGER.trace("retrying kXR_login after wait of {} seconds.", secs);
                sendLoginRequest(ctx);
                break;
            case kXR_open:
                LOGGER.trace("retrying kXR_open after wait of {} seconds.", secs);
                sendOpenRequest(ctx);
                break;
            case kXR_read:
                LOGGER.trace("retrying kXR_read after wait of {} seconds.", secs);
                sendReadRequest(ctx);
                break;
            case kXR_close:
                LOGGER.trace("retrying kXR_close after wait of {} seconds.", secs);
                sendCloseRequest(ctx);
                break;
            case kXR_endsess:
                LOGGER.trace("retrying kXR_endsess after wait of {} seconds.", secs);
                sendEndSessionRequest(ctx);
                break;
            default:
                String error = String.format("Retry after wait: (stream %s, request %s) "
                                                             + "should not have been received "
                                                             + "by tpc client",
                                             response.getStreamId(), requestId);
                handleServerDisconnect(ctx, error);
        }
    }

    protected void responseReceived(ChannelHandlerContext ctx,
                                  XrootdInboundResponse response)
    {
        LOGGER.trace("responseReceived for stream {}.", response.getStreamId());
        if (response instanceof InboundWaitResponse) {
            doOnWaitResponse(ctx, (InboundWaitResponse)response);
            return;
        }

        int requestId = response.getRequestId();
        switch (requestId) {
            case kXR_handshake:
                LOGGER.trace("responseReceived, requestId = kXR_handshake.");
                doOnHandshakeResponse(ctx, (HandshakeResponse) response);
                break;
            case kXR_auth:
                LOGGER.trace("responseReceived, requestId = kXR_auth.");
                doOnAuthenticationResponse(ctx, (InboundAuthenticationResponse) response);
                break;
            case kXR_login:
                LOGGER.trace("responseReceived, requestId = kXR_login.");
                doOnLoginResponse(ctx, (InboundLoginResponse) response);
                break;
            case kXR_open:
                LOGGER.trace("responseReceived, requestId = kXR_open.");
                doOnOpenResponse(ctx, (InboundOpenReadOnlyResponse) response);
                break;
            case kXR_read:
                LOGGER.trace("responseReceived, requestId = kXR_read.");
                doOnReadResponse(ctx, (InboundReadResponse) response);
                break;
            case kXR_close:
                LOGGER.trace("responseReceived, requestId = kXR_close.");
                doOnCloseResponse(ctx, (InboundCloseResponse) response);
                break;
            case kXR_endsess:
                LOGGER.trace("responseReceived, requestId = kXR_endsess.");
                doOnEndSessionResponse(ctx,
                                       (InboundEndSessionResponse) response);
                break;
            default:
                String error = String.format("Response (stream %s, request %s) "
                                                             + "should not have been received "
                                                             + "by tpc client",
                                             response.getStreamId(), requestId);
                handleServerDisconnect(ctx, error);
        }
    }

    protected void sendCloseRequest(ChannelHandlerContext ctx)
    {
        LOGGER.trace("sendCloseRequest to {}:{}, {}, {}.",
                     tpcInfo.getSrc(), tpcInfo.getSrcPort(), streamId, fhandle);
        decoder.setExpectedResponse(kXR_close);
        ctx.writeAndFlush(new OutboundCloseRequest(streamId, fhandle),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    protected void sendEndSessionRequest(ChannelHandlerContext ctx)
    {
        LOGGER.trace("sendEndSessionRequest to {}:{}, {}, {}.",
                     tpcInfo.getSrc(), tpcInfo.getSrcPort(), streamId, sessionId);
        decoder.setExpectedResponse(kXR_endsess);
        ctx.writeAndFlush(
                        new OutboundEndSessionRequest(streamId, sessionId),
                        ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    protected void sendHandshakeRequest(ChannelHandlerContext ctx)
    {
        LOGGER.trace("sendHandshakeRequest to {}:{}.",
                     tpcInfo.getSrc(), tpcInfo.getSrcPort());
        decoder.setExpectedResponse(kXR_handshake);
        ctx.writeAndFlush(new HandshakeRequest(),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    protected void sendLoginRequest(ChannelHandlerContext ctx)
    {
        LOGGER.trace("sendLoginRequest to {}:{}, {}, {}, {}, {}.",
                     tpcInfo.getSrc(), tpcInfo.getSrcPort(), streamId, pid, uname, null);
        decoder.setExpectedResponse(kXR_login);
        ctx.writeAndFlush(new OutboundLoginRequest(streamId, pid, uname, null),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    protected void sendOpenRequest(ChannelHandlerContext ctx)
    {
        LOGGER.trace("sendOpenRequest to {}:{}, {}, {}.",
                     tpcInfo.getSrc(), tpcInfo.getSrcPort(), streamId, fullpath);
        decoder.setExpectedResponse(kXR_open);
        ctx.writeAndFlush(new OutboundOpenReadOnlyRequest(streamId,
                                                          fullpath),
                          ctx.newPromise())
           .addListener(FIRE_EXCEPTION_ON_FAILURE);
    }

    /*
     *  TODO -- this should be implemented here, and not be abstract.
     */
    protected abstract void doOnAuthenticationResponse(ChannelHandlerContext ctx,
                                                       InboundAuthenticationResponse response);

    /**
     *  Should implement the proper read logic.  If vector reads are support,
     *  should direct to special method.
     */
    protected abstract void doOnReadResponse(ChannelHandlerContext ctx,
                                             InboundReadResponse response);

    /**
     *  Method is intended as error handling catch-all, so as to avoid
     *  generating extra exceptions.
     *
     *  Depending on how the client is implemented, the disconnect may require
     *  stopping the client as well.
     */
    protected abstract void handleServerDisconnect(ChannelHandlerContext ctx, String error);

    /*
     *  TODO -- this should be implemented here, and not be abstract.
     */
    protected abstract void sendAuthenticationRequest(ChannelHandlerContext ctx);

    /**
     *  Should take care of any special handling, such as vectorization.
     */
    protected abstract void sendReadRequest(ChannelHandlerContext ctx);

}

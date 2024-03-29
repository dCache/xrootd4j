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
package org.dcache.xrootd.core;

import static org.dcache.xrootd.core.AbstractXrootdDecoder.createException;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Unsupported;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_close;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_dirlist;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_locate;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_login;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mv;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_prepare;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_read;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_readv;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_rm;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_rmdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_set;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_stat;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_statx;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_sync;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_write;

import com.google.common.net.InetAddresses;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.codec.haproxy.HAProxyProxiedProtocol;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.util.Objects;
import javax.net.ssl.SSLException;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.FattrRequest;
import org.dcache.xrootd.protocol.messages.LocateRequest;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.QueryRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.SetRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ChannelInboundHandler to dispatch xrootd events to handler methods.
 * <p>
 * Default response to all request messages from a client is kXR_Unsupported. Sub-classes may
 * override handler methods to implement request handling.
 * <p>
 * Releases the reference to XrootdRequest if the handler method throws an exception or returns a
 * response. If the handler returns null the subclass assumes responsibility to release the request,
 * typically by passing it on the next ChannelHandler in the pipeline.
 */
public class XrootdRequestHandler extends ChannelInboundHandlerAdapter {

    private static final Logger _log =
          LoggerFactory.getLogger(XrootdRequestHandler.class);

    private boolean _isHealthCheck;

    private InetSocketAddress _destinationAddress;

    private InetSocketAddress _sourceAddress;

    private String sessionToken;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        _destinationAddress = (InetSocketAddress) ctx.channel().localAddress();
        _sourceAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof XrootdRequest) {
            requestReceived(ctx, (XrootdRequest) msg);
        } else if (msg instanceof HAProxyMessage) {
            HAProxyMessage proxyMessage = (HAProxyMessage) msg;
            switch (proxyMessage.command()) {
                case LOCAL:
                    _isHealthCheck = true;
                    break;
                case PROXY:
                    String sourceAddress = proxyMessage.sourceAddress();
                    String destinationAddress = proxyMessage.destinationAddress();
                    InetSocketAddress localAddress = (InetSocketAddress) ctx.channel()
                          .localAddress();
                    if (proxyMessage.proxiedProtocol() == HAProxyProxiedProtocol.TCP4 ||
                          proxyMessage.proxiedProtocol() == HAProxyProxiedProtocol.TCP6) {
                        if (Objects.equals(destinationAddress,
                              localAddress.getAddress().getHostAddress())) {
                            /* Workaround for what looks like a bug in HAProxy - health checks should
                             * generate a LOCAL command, but it appears they do actually use PROXY.
                             */
                            _isHealthCheck = true;
                        } else {
                            _destinationAddress = new InetSocketAddress(
                                  InetAddresses.forString(destinationAddress),
                                  proxyMessage.destinationPort());
                            _sourceAddress = new InetSocketAddress(
                                  InetAddresses.forString(sourceAddress),
                                  proxyMessage.sourcePort());
                        }
                    }
                    break;
            }
            ctx.fireChannelRead(msg);
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if (cause instanceof SSLException) {
            super.exceptionCaught(ctx, createException(ctx, (SSLException) cause, sessionToken));
        } else {
            super.exceptionCaught(ctx, cause);
        }
    }

    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SSLException) {
            _log.error("userEvent {}.", createException(ctx, (SSLException) evt, sessionToken));
        } else if (evt instanceof SslHandshakeCompletionEvent) {
            if (!((SslHandshakeCompletionEvent) evt).isSuccess()) {
                Throwable t = ((SslHandshakeCompletionEvent) evt).cause();
                if (!(t instanceof ClosedChannelException)) {
                    _log.error("TLS handshake failed: {}.",
                          t == null ? "no cause reported" : t.toString());
                }
            }
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

    protected void requestReceived(ChannelHandlerContext ctx, XrootdRequest req) {
        try {
            Object response = getResponse(ctx, req);
            if (response != null) {
                respond(ctx, response);
            } else {
                req = null; // Do not release reference
            }
        } catch (XrootdException e) {
            respond(ctx, withError(ctx, req, e.getError(), e.getMessage()));
        } catch (Exception e) {
            _log.error("xrootd server error while processing " + req
                  + " (please report this to support@dcache.org)", e);
            respond(ctx,
                  withError(ctx, req, kXR_ServerError,
                        String.format("Internal server error (%s)",
                              e.getMessage())));
        } finally {
            ReferenceCountUtil.release(req);
        }
    }

    protected Object getResponse(ChannelHandlerContext ctx, XrootdRequest req)
          throws Exception {
        switch (req.getRequestId()) {
            case kXR_auth:
                return doOnAuthentication(ctx, (AuthenticationRequest) req);
            case kXR_login:
                LoginRequest loginRequest = (LoginRequest) req;
                sessionToken = loginRequest.getToken();
                return doOnLogin(ctx, loginRequest);
            case kXR_open:
                return doOnOpen(ctx, (OpenRequest) req);
            case kXR_stat:
                return doOnStat(ctx, (StatRequest) req);
            case kXR_statx:
                return doOnStatx(ctx, (StatxRequest) req);
            case kXR_read:
                return doOnRead(ctx, (ReadRequest) req);
            case kXR_readv:
                return doOnReadV(ctx, (ReadVRequest) req);
            case kXR_write:
                return doOnWrite(ctx, (WriteRequest) req);
            case kXR_sync:
                return doOnSync(ctx, (SyncRequest) req);
            case kXR_close:
                return doOnClose(ctx, (CloseRequest) req);
            case kXR_protocol:
                return doOnProtocolRequest(ctx, (ProtocolRequest) req);
            case kXR_rm:
                return doOnRm(ctx, (RmRequest) req);
            case kXR_rmdir:
                return doOnRmDir(ctx, (RmDirRequest) req);
            case kXR_mkdir:
                return doOnMkDir(ctx, (MkDirRequest) req);
            case kXR_mv:
                return doOnMv(ctx, (MvRequest) req);
            case kXR_dirlist:
                return doOnDirList(ctx, (DirListRequest) req);
            case kXR_prepare:
                return doOnPrepare(ctx, (PrepareRequest) req);
            case kXR_locate:
                return doOnLocate(ctx, (LocateRequest) req);
            case kXR_query:
                return doOnQuery(ctx, (QueryRequest) req);
            case kXR_set:
                return doOnSet(ctx, (SetRequest) req);
            case kXR_endsess:
                return doOnEndSession(ctx, (EndSessionRequest) req);
            case kXR_fattr:
                return doOnFattr(ctx, (FattrRequest) req);
            default:
                return unsupported(ctx, req);
        }
    }

    protected <T extends XrootdRequest> OkResponse<T> withOk(T req) {
        return new OkResponse<>(req);
    }

    protected <T extends XrootdRequest> ErrorResponse<T> withError(ChannelHandlerContext ctx, T req,
          int errorCode, String errMsg) {
        return new ErrorResponse<>(ctx, req, errorCode, errMsg);
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx, Object response) {
        return ctx.writeAndFlush(response)
              .addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
    }

    protected <T extends XrootdRequest> XrootdResponse<T> unsupported(ChannelHandlerContext ctx,
          T msg)
          throws XrootdException {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported,
              "Request " + msg.getRequestId() + " not supported");
    }

    protected Object doOnLogin(ChannelHandlerContext ctx,
          LoginRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnAuthentication(ChannelHandlerContext ctx,
          AuthenticationRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnOpen(ChannelHandlerContext ctx,
          OpenRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnFattr(ChannelHandlerContext ctx,
          FattrRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnStat(ChannelHandlerContext ctx,
          StatRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnStatx(ChannelHandlerContext ctx,
          StatxRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnRead(ChannelHandlerContext ctx,
          ReadRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnReadV(ChannelHandlerContext ctx,
          ReadVRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnWrite(ChannelHandlerContext ctx,
          WriteRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnSync(ChannelHandlerContext ctx,
          SyncRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnClose(ChannelHandlerContext ctx,
          CloseRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnProtocolRequest(ChannelHandlerContext ctx,
          ProtocolRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnRm(ChannelHandlerContext ctx,
          RmRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnRmDir(ChannelHandlerContext ctx,
          RmDirRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnMkDir(ChannelHandlerContext ctx,
          MkDirRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnMv(ChannelHandlerContext ctx,
          MvRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnDirList(ChannelHandlerContext ctx,
          DirListRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnPrepare(ChannelHandlerContext ctx,
          PrepareRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnLocate(ChannelHandlerContext ctx,
          LocateRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnQuery(ChannelHandlerContext ctx,
          QueryRequest msg)
          throws XrootdException {
        return unsupported(ctx, msg);
    }

    protected Object doOnSet(ChannelHandlerContext ctx,
          SetRequest request)
          throws XrootdException {
        return unsupported(ctx, request);
    }

    protected Object doOnEndSession(ChannelHandlerContext ctx,
          EndSessionRequest request)
          throws XrootdException {
        return unsupported(ctx, request);
    }

    /**
     * The socket address the client connected to. May be the local address of the channel, but
     * could also be an address on a proxy server between the client and the server.
     */
    protected InetSocketAddress getDestinationAddress() {
        return _destinationAddress;
    }

    /**
     * The socket address the client connected from. May be the remote address of the channel, but
     * in case a proxy is in between the client and the server, the source address will be a
     * different from the remote address.
     */
    protected InetSocketAddress getSourceAddress() {
        return _sourceAddress;
    }

    /**
     * True if this looks like a health check connection from a proxy server.
     */
    protected boolean isHealthCheck() {
        return _isHealthCheck;
    }
}

/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.core;

import com.google.common.net.InetAddresses;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.codec.haproxy.HAProxyProxiedProtocol;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.Objects;

import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.EndSessionRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A ChannelInboundHandler to dispatch xrootd events to handler methods.
 *
 * Default response to all request messages from a client is
 * kXR_Unsupported. Sub-classes may override handler methods to
 * implement request handling.
 *
 * Releases the reference to XrootdRequest if the handler method throws
 * an exception or returns a response. If the handler returns null the
 * subclass assumes responsibility to release the request, typically
 * by passing it on the next ChannelHandler in the pipeline.
 */
public class XrootdRequestHandler extends ChannelInboundHandlerAdapter
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdRequestHandler.class);

    private boolean _isHealthCheck;

    private InetSocketAddress _destinationAddress;

    private InetSocketAddress _sourceAddress;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception
    {
        _destinationAddress = (InetSocketAddress) ctx.channel().localAddress();
        _sourceAddress = (InetSocketAddress) ctx.channel().remoteAddress();
        super.channelActive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception
    {
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
                InetSocketAddress localAddress = (InetSocketAddress) ctx.channel().localAddress();
                if (proxyMessage.proxiedProtocol() == HAProxyProxiedProtocol.TCP4 ||
                    proxyMessage.proxiedProtocol() == HAProxyProxiedProtocol.TCP6) {
                    if (Objects.equals(destinationAddress, localAddress.getAddress().getHostAddress())) {
                        /* Workaround for what looks like a bug in HAProxy - health checks should
                         * generate a LOCAL command, but it appears they do actually use PROXY.
                         */
                        _isHealthCheck = true;
                    } else {
                        _destinationAddress = new InetSocketAddress(InetAddresses.forString(destinationAddress), proxyMessage.destinationPort());
                        _sourceAddress = new InetSocketAddress(InetAddresses.forString(sourceAddress), proxyMessage.sourcePort());
                    }
                }
                break;
            }
            ctx.fireChannelRead(msg);
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception
    {
        if (evt instanceof SslHandshakeCompletionEvent) {
            if (!((SslHandshakeCompletionEvent) evt).isSuccess()) {
                Throwable t = ((SslHandshakeCompletionEvent) evt).cause();
                _log.error("TLS handshake failed: {}.",
                          t == null ? "no cause reported" : t.toString());
            }
        } else {
            super.userEventTriggered(ctx, evt);
        }
    }

    protected void requestReceived(ChannelHandlerContext ctx, XrootdRequest req)
    {
        try {
            Object response;
            switch (req.getRequestId()) {
            case kXR_auth:
                response =
                    doOnAuthentication(ctx, (AuthenticationRequest) req);
                break;
            case kXR_login:
                response =
                    doOnLogin(ctx, (LoginRequest) req);
                break;
            case kXR_open:
                response =
                    doOnOpen(ctx, (OpenRequest) req);
                break;
            case kXR_stat:
                response =
                    doOnStat(ctx, (StatRequest) req);
                break;
            case kXR_statx:
                response =
                    doOnStatx(ctx, (StatxRequest) req);
                break;
            case kXR_read:
                response =
                    doOnRead(ctx, (ReadRequest) req);
                break;
            case kXR_readv:
                response =
                    doOnReadV(ctx, (ReadVRequest) req);
                break;
            case kXR_write:
                response =
                    doOnWrite(ctx, (WriteRequest) req);
                break;
            case kXR_sync:
                response =
                    doOnSync(ctx, (SyncRequest) req);
                break;
            case kXR_close:
                response =
                    doOnClose(ctx, (CloseRequest) req);
                break;
            case kXR_protocol:
                response =
                    doOnProtocolRequest(ctx, (ProtocolRequest) req);
                _log.debug("PROTOCOL RESPONSE TO CLIENT {}.", response);
                break;
            case kXR_rm:
                response =
                    doOnRm(ctx, (RmRequest) req);
                break;
            case kXR_rmdir:
                response =
                    doOnRmDir(ctx, (RmDirRequest) req);
                break;
            case kXR_mkdir:
                response =
                    doOnMkDir(ctx, (MkDirRequest) req);
                break;
            case kXR_mv:
                response =
                    doOnMv(ctx, (MvRequest) req);
                break;
            case kXR_dirlist:
                response =
                    doOnDirList(ctx, (DirListRequest) req);
                break;
            case kXR_prepare:
                response =
                    doOnPrepare(ctx, (PrepareRequest) req);
                break;
            case kXR_locate :
                response =
                        doOnLocate(ctx, (LocateRequest) req);
                break;
            case kXR_query :
                response =
                        doOnQuery(ctx, (QueryRequest) req);
                break;
            case kXR_set :
                response =
                        doOnSet(ctx, (SetRequest) req);
                break;
            case kXR_endsess:
                response =
                        doOnEndSession(ctx, (EndSessionRequest) req);
                break;
            default:
                response =
                    unsupported(ctx, req);
                break;
            }
            if (response != null) {
                respond(ctx, response);
            } else {
                req = null; // Do not release reference
            }
        } catch (XrootdException e) {
            respond(ctx, withError(req, e.getError(), e.getMessage()));
        } catch (RuntimeException e) {
            _log.error("xrootd server error while processing " + req + " (please report this to support@dcache.org)", e);
            respond(ctx,
                withError(req, kXR_ServerError,
                    String.format("Internal server error (%s)",
                        e.getMessage())));
        } finally {
            ReferenceCountUtil.release(req);
        }
    }

    protected <T extends XrootdRequest> OkResponse<T> withOk(T req)
    {
        return new OkResponse<>(req);
    }

    protected <T extends XrootdRequest> ErrorResponse<T> withError(T req, int errorCode, String errMsg)
    {
        return new ErrorResponse<>(req, errorCode, errMsg);
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx, Object response)
    {
        return ctx.writeAndFlush(response).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
    }

    protected <T extends XrootdRequest> XrootdResponse<T> unsupported(ChannelHandlerContext ctx, T msg)
        throws XrootdException
    {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported, "Request " + msg.getRequestId() + " not supported");
    }

    protected Object doOnLogin(ChannelHandlerContext ctx,
                               LoginRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnAuthentication(ChannelHandlerContext ctx,
                                        AuthenticationRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnOpen(ChannelHandlerContext ctx,
                              OpenRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnStat(ChannelHandlerContext ctx,
                              StatRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnStatx(ChannelHandlerContext ctx,
                               StatxRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnRead(ChannelHandlerContext ctx,
                              ReadRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnReadV(ChannelHandlerContext ctx,
                               ReadVRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnWrite(ChannelHandlerContext ctx,
                               WriteRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnSync(ChannelHandlerContext ctx,
                              SyncRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnClose(ChannelHandlerContext ctx,
                               CloseRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnProtocolRequest(ChannelHandlerContext ctx,
                                         ProtocolRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnRm(ChannelHandlerContext ctx,
                            RmRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnRmDir(ChannelHandlerContext ctx,
                               RmDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnMkDir(ChannelHandlerContext ctx,
                               MkDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnMv(ChannelHandlerContext ctx,
                            MvRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnDirList(ChannelHandlerContext ctx,
                                 DirListRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnPrepare(ChannelHandlerContext ctx,
                                 PrepareRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnLocate(ChannelHandlerContext ctx,
                                LocateRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnQuery(ChannelHandlerContext ctx,
                               QueryRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, msg);
    }

    protected Object doOnSet(ChannelHandlerContext ctx,
                             SetRequest request)
            throws XrootdException
    {
        return unsupported(ctx, request);
    }

    protected Object doOnEndSession(ChannelHandlerContext ctx,
                                    EndSessionRequest request)
            throws XrootdException
    {
        return unsupported(ctx, request);
    }

    /**
     * The socket address the client connected to. May be the local address
     * of the channel, but could also be an address on a proxy server
     * between the client and the server.
     */
    protected InetSocketAddress getDestinationAddress()
    {
        return _destinationAddress;
    }

    /**
     * The socket address the client connected from. May be the remote address
     * of the channel, but in case a proxy is in between the client and the
     * server, the source address will be a different from the remote address.
     */
    protected InetSocketAddress getSourceAddress()
    {
        return _sourceAddress;
    }

    /**
     * True if this looks like a health check connection from a proxy server.
     */
    protected boolean isHealthCheck()
    {
        return _isHealthCheck;
    }
}

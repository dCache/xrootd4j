/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.core;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundMessageHandlerAdapter;
import io.netty.handler.timeout.IdleStateEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
import org.dcache.xrootd.protocol.messages.ErrorResponse;
import org.dcache.xrootd.protocol.messages.LoginRequest;
import org.dcache.xrootd.protocol.messages.MkDirRequest;
import org.dcache.xrootd.protocol.messages.MvRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.protocol.messages.OpenRequest;
import org.dcache.xrootd.protocol.messages.PrepareRequest;
import org.dcache.xrootd.protocol.messages.ProtocolRequest;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.RmDirRequest;
import org.dcache.xrootd.protocol.messages.RmRequest;
import org.dcache.xrootd.protocol.messages.StatRequest;
import org.dcache.xrootd.protocol.messages.StatxRequest;
import org.dcache.xrootd.protocol.messages.SyncRequest;
import org.dcache.xrootd.protocol.messages.WriteRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A ChannelInboundMessageHandler that dispatches xrootd requests to handler methods.
 *
 * Default response to all request messages from a client is
 * kXR_Unsupported. Sub-classes may override handler methods to
 * implement request handling.
 */
public class XrootdRequestHandler extends ChannelInboundMessageHandlerAdapter<XrootdRequest>
{
    private final static Logger _log =
        LoggerFactory.getLogger(XrootdRequestHandler.class);

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
        if (evt instanceof IdleStateEvent) {
        }
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, XrootdRequest req)
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
            default:
                response =
                    unsupported(ctx, req);
                break;
            }
            if (response != null) {
                respond(ctx, response);
            }
        } catch (XrootdException e) {
            respond(ctx, withError(req, e.getError(), e.getMessage()));
        } catch (RuntimeException e) {
            _log.error(String.format("Processing %s failed due to a bug", req), e);
            respond(ctx,
                withError(req, kXR_ServerError,
                    String.format("Internal server error (%s)",
                        e.getMessage())));
        }
    }

    protected OkResponse withOk(XrootdRequest req)
    {
        return new OkResponse(req);
    }

    protected ErrorResponse withError(XrootdRequest req, int errorCode, String errMsg)
    {
        return new ErrorResponse(req, errorCode, errMsg);
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx,
                                    Object response)
    {
        return ctx.channel().write(response);
    }

    protected Object unsupported(ChannelHandlerContext ctx,
                                 XrootdRequest msg)
        throws XrootdException
    {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported,
            "Request " + msg.getRequestId() + " not supported");
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
}

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

import com.google.common.base.Strings;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.timeout.IdleStateAwareChannelHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.CloseRequest;
import org.dcache.xrootd.protocol.messages.DirListRequest;
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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A SimpleChannelHandler dispatch xrootd events to handler methods.
 *
 * Default response to all request messages from a client is
 * kXR_Unsupported. Sub-classes may override handler methods to
 * implement request handling.
 */
public class XrootdRequestHandler extends IdleStateAwareChannelHandler
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdRequestHandler.class);

    public XrootdRequestHandler()
    {
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent event)
    {
        Object msg = event.getMessage();
        if (msg instanceof XrootdRequest) {
            requestReceived(ctx, event, (XrootdRequest) msg);
        }
    }

    protected void requestReceived(ChannelHandlerContext ctx,
                                   MessageEvent event,
                                   XrootdRequest req)
    {
        try {
            Object response;
            switch (req.getRequestId()) {
            case kXR_auth:
                response =
                    doOnAuthentication(ctx, event, (AuthenticationRequest) req);
                break;
            case kXR_login:
                response =
                    doOnLogin(ctx, event, (LoginRequest) req);
                break;
            case kXR_open:
                response =
                    doOnOpen(ctx, event, (OpenRequest) req);
                break;
            case kXR_stat:
                response =
                    doOnStat(ctx, event, (StatRequest) req);
                break;
            case kXR_statx:
                response =
                    doOnStatx(ctx, event, (StatxRequest) req);
                break;
            case kXR_read:
                response =
                    doOnRead(ctx, event, (ReadRequest) req);
                break;
            case kXR_readv:
                response =
                    doOnReadV(ctx, event, (ReadVRequest) req);
                break;
            case kXR_write:
                response =
                    doOnWrite(ctx, event, (WriteRequest) req);
                break;
            case kXR_sync:
                response =
                    doOnSync(ctx, event, (SyncRequest) req);
                break;
            case kXR_close:
                response =
                    doOnClose(ctx, event, (CloseRequest) req);
                break;
            case kXR_protocol:
                response =
                    doOnProtocolRequest(ctx, event, (ProtocolRequest) req);
                break;
            case kXR_rm:
                response =
                    doOnRm(ctx, event, (RmRequest) req);
                break;
            case kXR_rmdir:
                response =
                    doOnRmDir(ctx, event, (RmDirRequest) req);
                break;
            case kXR_mkdir:
                response =
                    doOnMkDir(ctx, event, (MkDirRequest) req);
                break;
            case kXR_mv:
                response =
                    doOnMv(ctx, event, (MvRequest) req);
                break;
            case kXR_dirlist:
                response =
                    doOnDirList(ctx, event, (DirListRequest) req);
                break;
            case kXR_prepare:
                response =
                    doOnPrepare(ctx, event, (PrepareRequest) req);
                break;
            case kXR_locate :
                response =
                        doOnLocate(ctx, event, (LocateRequest) req);
                break;
            case kXR_query :
                response =
                        doOnQuery(ctx, event, (QueryRequest) req);
                break;
            case kXR_set :
                response =
                        doOnSet(ctx, event, (SetRequest) req);
            default:
                response =
                    unsupported(ctx, event, req);
                break;
            }
            if (response != null) {
                respond(ctx, event, response);
            }
        } catch (XrootdException e) {
            respond(ctx, event, withError(req, e.getError(), e.getMessage()));
        } catch (RuntimeException e) {
            _log.error("xrootd server error while processing " + req + " (please report this to support@dcache.org)", e);
            respond(ctx, event,
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
        return new ErrorResponse(req, errorCode, Strings.nullToEmpty(errMsg));
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx,
                                    MessageEvent e,
                                    Object response)
    {
        return e.getChannel().write(response);
    }

    protected Object unsupported(ChannelHandlerContext ctx,
                                 MessageEvent e,
                                 XrootdRequest msg)
        throws XrootdException
    {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported,
            "Request " + msg.getRequestId() + " not supported");
    }

    protected Object doOnLogin(ChannelHandlerContext ctx,
                               MessageEvent e,
                               LoginRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnAuthentication(ChannelHandlerContext ctx,
                                        MessageEvent e,
                                        AuthenticationRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnOpen(ChannelHandlerContext ctx,
                              MessageEvent e,
                              OpenRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnStat(ChannelHandlerContext ctx,
                              MessageEvent e,
                              StatRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnStatx(ChannelHandlerContext ctx,
                               MessageEvent e,
                               StatxRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnRead(ChannelHandlerContext ctx,
                              MessageEvent e,
                              ReadRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnReadV(ChannelHandlerContext ctx,
                               MessageEvent e,
                               ReadVRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnWrite(ChannelHandlerContext ctx,
                               MessageEvent e,
                               WriteRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnSync(ChannelHandlerContext ctx,
                              MessageEvent e,
                              SyncRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnClose(ChannelHandlerContext ctx,
                               MessageEvent e,
                               CloseRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnProtocolRequest(ChannelHandlerContext ctx,
                                         MessageEvent e,
                                         ProtocolRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnRm(ChannelHandlerContext ctx,
                            MessageEvent e,
                            RmRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnRmDir(ChannelHandlerContext ctx,
                               MessageEvent e,
                               RmDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnMkDir(ChannelHandlerContext ctx,
                               MessageEvent e,
                               MkDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnMv(ChannelHandlerContext ctx,
                            MessageEvent e,
                            MvRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnDirList(ChannelHandlerContext ctx,
                                 MessageEvent e,
                                 DirListRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnPrepare(ChannelHandlerContext ctx,
                                 MessageEvent e,
                                 PrepareRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnLocate(ChannelHandlerContext ctx,
                                MessageEvent e,
                                LocateRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnQuery(ChannelHandlerContext ctx,
                               MessageEvent e,
                               QueryRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected Object doOnSet(ChannelHandlerContext ctx, MessageEvent event, SetRequest request)
            throws XrootdException
    {
        return unsupported(ctx, event, request);
    }
}

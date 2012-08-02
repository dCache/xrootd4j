/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.timeout.IdleStateAwareChannelHandler;

import org.dcache.xrootd.protocol.messages.*;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SimpleChannelHandler dispatch xrootd events to handler methods.
 *
 * Default response to all request messages from a client is
 * kXR_Unsupported. Sub-classes may override handler methods to
 * implement request handling.
 */
public class XrootdRequestHandler extends IdleStateAwareChannelHandler
{
    private final static Logger _log =
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
            AbstractResponseMessage response;
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
            _log.error(String.format("Processing %s failed due to a bug", req), e);
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

    protected ErrorResponse
        withError(XrootdRequest req, int errorCode, String errMsg)
    {
        return new ErrorResponse(req, errorCode, errMsg);
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx,
                                    MessageEvent e,
                                    AbstractResponseMessage msg)
    {
        return e.getChannel().write(msg);
    }

    protected AbstractResponseMessage unsupported(ChannelHandlerContext ctx,
                                                  MessageEvent e,
                                                  XrootdRequest msg)
        throws XrootdException
    {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported,
                                  "Request " + msg.getRequestId() + " not supported");
    }

    protected AbstractResponseMessage doOnLogin(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                LoginRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnAuthentication(ChannelHandlerContext ctx,
                                                         MessageEvent e,
                                                         AuthenticationRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnOpen(ChannelHandlerContext ctx,
                                               MessageEvent e,
                                               OpenRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnStat(ChannelHandlerContext ctx,
                                               MessageEvent e,
                                               StatRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnStatx(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                StatxRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnRead(ChannelHandlerContext ctx,
                                               MessageEvent e,
                                               ReadRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnReadV(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                ReadVRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnWrite(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                WriteRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnSync(ChannelHandlerContext ctx,
                                               MessageEvent e,
                                               SyncRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnClose(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                CloseRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnProtocolRequest(ChannelHandlerContext ctx,
                                                          MessageEvent e,
                                                          ProtocolRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnRm(ChannelHandlerContext ctx,
                                             MessageEvent e,
                                             RmRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnRmDir(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                RmDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnMkDir(ChannelHandlerContext ctx,
                                                MessageEvent e,
                                                MkDirRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnMv(ChannelHandlerContext ctx,
                                             MessageEvent e,
                                             MvRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnDirList(ChannelHandlerContext ctx,
                                                  MessageEvent e,
                                                  DirListRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }

    protected AbstractResponseMessage doOnPrepare(ChannelHandlerContext ctx,
                                                  MessageEvent e,
                                                  PrepareRequest msg)
        throws XrootdException
    {
        return unsupported(ctx, e, msg);
    }
}
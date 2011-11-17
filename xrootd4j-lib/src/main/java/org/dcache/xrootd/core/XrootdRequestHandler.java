/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.handler.timeout.IdleStateAwareChannelHandler;

import org.dcache.xrootd.protocol.messages.*;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A SimpleChannelHandler which provides an individual handler method
 * for each xrootd request type.
 *
 * Default respons to all requests is kXR_Unsupported. Sub-classes
 * may override handler methods to implement request handling.
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
        AbstractRequestMessage msg =
            (AbstractRequestMessage) event.getMessage();

        try {
            /* FIXME: can dispatching be done in a nicer way? */
            AbstractResponseMessage response;
            if (msg instanceof AuthenticationRequest) {
                response =
                    doOnAuthentication(ctx, event, (AuthenticationRequest) msg);
            } else if (msg instanceof LoginRequest) {
                response =
                    doOnLogin(ctx, event, (LoginRequest) msg);
            } else if (msg instanceof OpenRequest) {
                response =
                    doOnOpen(ctx, event, (OpenRequest) msg);
            } else if (msg instanceof StatRequest) {
                response =
                    doOnStat(ctx, event, (StatRequest) msg);
            } else if (msg instanceof StatxRequest) {
                response =
                    doOnStatx(ctx, event, (StatxRequest) msg);
            } else if (msg instanceof ReadRequest) {
                response =
                    doOnRead(ctx, event, (ReadRequest) msg);
            } else if (msg instanceof ReadVRequest) {
                response =
                    doOnReadV(ctx, event, (ReadVRequest) msg);
            } else if (msg instanceof WriteRequest) {
                response =
                    doOnWrite(ctx, event, (WriteRequest) msg);
            } else if (msg instanceof SyncRequest) {
                response =
                    doOnSync(ctx, event, (SyncRequest) msg);
            } else if (msg instanceof CloseRequest) {
                response =
                    doOnClose(ctx, event, (CloseRequest) msg);
            } else if (msg instanceof ProtocolRequest) {
                response =
                    doOnProtocolRequest(ctx, event, (ProtocolRequest) msg);
            } else if (msg instanceof RmRequest) {
                response =
                    doOnRm(ctx, event, (RmRequest) msg);
            } else if (msg instanceof RmDirRequest) {
                response =
                    doOnRmDir(ctx, event, (RmDirRequest) msg);
            } else if (msg instanceof MkDirRequest) {
                response =
                    doOnMkDir(ctx, event, (MkDirRequest) msg);
            } else if (msg instanceof MvRequest) {
                response =
                    doOnMv(ctx, event, (MvRequest) msg);
            } else if (msg instanceof DirListRequest) {
                response =
                    doOnDirList(ctx, event, (DirListRequest) msg);
            } else if (msg instanceof PrepareRequest) {
                response =
                    doOnPrepare(ctx, event, (PrepareRequest) msg);
            } else {
                response =
                    unsupported(ctx, event, msg);
            }
            if (response != null) {
                respond(ctx, event, response);
            }
        } catch (XrootdException e) {
            respondWithError(ctx, event, msg, e.getError(), e.getMessage());
        } catch (RuntimeException e) {
            _log.error(String.format("Processing %s failed due to a bug", msg), e);
            respondWithError(ctx, event, msg, kXR_ServerError,
                             String.format("Internal server error (%s)",
                                           e.getMessage()));
        }
    }

    protected ChannelFuture respond(ChannelHandlerContext ctx,
                                    MessageEvent e,
                                    AbstractResponseMessage msg)
    {
        return e.getChannel().write(msg);
    }

    protected ChannelFuture respondWithError(ChannelHandlerContext ctx,
                                             MessageEvent e,
                                             AbstractRequestMessage msg,
                                             int errorCode, String errMsg)
    {
        return respond(ctx, e,
                       new ErrorResponse(msg.getStreamID(), errorCode, errMsg));
    }

    protected ChannelFuture closeWithError(ChannelHandlerContext ctx,
                                           MessageEvent e,
                                           AbstractRequestMessage msg,
                                           int errorCode, String errMsg)
    {
        ChannelFuture f = respondWithError(ctx, e, msg, errorCode, errMsg);
        f.addListener(ChannelFutureListener.CLOSE);
        return f;
    }

    protected AbstractResponseMessage unsupported(ChannelHandlerContext ctx,
                                                  MessageEvent e,
                                                  AbstractRequestMessage msg)
        throws XrootdException
    {
        _log.warn("Unsupported request: " + msg);
        throw new XrootdException(kXR_Unsupported,
                                  "Request " + msg.getRequestID() + " not supported");
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
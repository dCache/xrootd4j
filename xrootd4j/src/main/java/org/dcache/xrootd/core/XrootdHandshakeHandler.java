/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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

import java.util.Arrays;


import static org.jboss.netty.channel.Channels.*;
import static org.jboss.netty.buffer.ChannelBuffers.*;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;

import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.HandshakeRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ChannelHandler which recognizes the xrootd handshake and
 * generates an appropriate response. Once handshaked, all messages
 * are passed on. Failure to handshake causes the channel to be
 * closed.
 */
public class XrootdHandshakeHandler extends SimpleChannelUpstreamHandler
{
    private static final Logger _log =
        LoggerFactory.getLogger(XrootdHandshakeHandler.class);

    private final int _serverType;
    private boolean _isHandshaked;

    public XrootdHandshakeHandler(int serverType)
    {
        _serverType = serverType;
        _isHandshaked = false;
    }

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e)
        throws Exception
    {
        Object msg = e.getMessage();

        if (!_isHandshaked) {
            if (!(msg instanceof HandshakeRequest)) {
                _log.error("Invalid handshake");
                close(ctx, e.getFuture());
                return;
            }

            byte[] request = ((HandshakeRequest) msg).getHandshake();
            if (!Arrays.equals(request, HANDSHAKE_REQUEST)) {
                _log.error("Received corrupt handshake message ("
                           + request.length + " bytes).");
                close(ctx, e.getFuture());
                return;
            }

            byte[] response;
            switch (_serverType) {
            case LOAD_BALANCER:
                response = HANDSHAKE_RESPONSE_LOADBALANCER;
                break;

            case DATA_SERVER:
                response = HANDSHAKE_RESPONSE_DATASERVER;
                break;

            default:
                _log.error("Unknown server type (" + _serverType + ")");
                close(ctx, e.getFuture());
                return;
            }

            write(ctx, e.getFuture(), wrappedBuffer(response));

            _isHandshaked = true;

            return;
        }

        super.messageReceived(ctx, e);
    }
}

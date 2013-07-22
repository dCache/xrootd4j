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

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundMessageHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import org.dcache.xrootd.protocol.messages.HandshakeRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

import static io.netty.buffer.Unpooled.wrappedBuffer;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A ChannelHandler which recognizes the xrootd handshake and
 * generates an appropriate response. Once handshaked, all messages
 * are passed on. Failure to handshake causes the channel to be
 * closed.
 */
public class XrootdHandshakeHandler extends ChannelInboundMessageHandlerAdapter<XrootdRequest>
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
    public void messageReceived(ChannelHandlerContext ctx, XrootdRequest msg)
        throws Exception
    {
        if (!_isHandshaked) {
            if (!(msg instanceof HandshakeRequest)) {
                _log.error("Invalid handshake");
                ctx.channel().close();
                return;
            }

            byte[] request = ((HandshakeRequest) msg).getHandshake();
            if (!Arrays.equals(request, HANDSHAKE_REQUEST)) {
                _log.error("Received corrupt handshake message ("
                           + request.length + " bytes).");
                ctx.channel().close();
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
                ctx.channel().close();
                return;
            }

            ctx.channel().write(wrappedBuffer(response));

            _isHandshaked = true;

            return;
        }

        ctx.nextInboundMessageBuffer().add(msg);
    }
}

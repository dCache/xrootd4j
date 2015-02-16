/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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

import java.util.Arrays;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;

import org.dcache.xrootd.protocol.messages.XrootdRequest;
import org.dcache.xrootd.protocol.messages.HandshakeRequest;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ChannelHandler which recognizes the xrootd handshake and
 * generates an appropriate response. Once handshaked, all messages
 * are passed on. Failure to handshake causes the channel to be
 * closed.
 */
public class XrootdHandshakeHandler extends ChannelInboundHandlerAdapter
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
    public void channelRead(ChannelHandlerContext ctx, Object obj) throws Exception
    {
        XrootdRequest msg = (XrootdRequest) obj;

        if (!_isHandshaked) {
            try {
                if (!(msg instanceof HandshakeRequest)) {
                    _log.error("Invalid handshake");
                    ctx.close();
                    return;
                }

                byte[] request = ((HandshakeRequest) msg).getHandshake();
                if (!Arrays.equals(request, HANDSHAKE_REQUEST)) {
                    _log.error("Received corrupt handshake message ("
                               + request.length + " bytes).");
                    ctx.close();
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
                    ctx.close();
                    return;
                }

                ctx.writeAndFlush(Unpooled.wrappedBuffer(response));

                _isHandshaked = true;

                return;
            } finally {
                ReferenceCountUtil.release(msg);
            }
        }

        super.channelRead(ctx, msg);
    }
}

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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * A ChannelHandler which recognizes the xrootd handshake and generates an
 * appropriate response. Once handshaked, the handler removes itself from
 * the pipeline. Failure to handshake causes the channel to be closed.
 */
public class XrootdHandshakeHandler extends ByteToMessageDecoder
{
    private static final Logger LOGGER =
        LoggerFactory.getLogger(XrootdHandshakeHandler.class);

    private final byte[] response;

    public XrootdHandshakeHandler(int serverType)
    {
        switch (serverType) {
        case LOAD_BALANCER:
            response = HANDSHAKE_RESPONSE_LOADBALANCER;
            break;
        case DATA_SERVER:
            response = HANDSHAKE_RESPONSE_DATASERVER;
            break;
        default:
            throw new IllegalArgumentException("Unknown server type: " + serverType);
        }
    }

    @Override
    protected final void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) throws Exception
    {
        if (in.readableBytes() >= CLIENT_HANDSHAKE_LEN) {
            byte[] handshake = new byte[20];
            in.readBytes(handshake);

            if (!Arrays.equals(handshake, HANDSHAKE_REQUEST)) {
                in.clear();
                LOGGER.warn("{} Received invalid handshake.", ctx.channel());
                ctx.close();
                return;
            }

            ctx.writeAndFlush(Unpooled.wrappedBuffer(response));
            ctx.channel().pipeline().remove(this);
        }
    }
}

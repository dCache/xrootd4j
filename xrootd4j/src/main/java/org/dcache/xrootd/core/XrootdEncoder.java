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

import static org.jboss.netty.channel.Channels.*;

import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.buffer.ChannelBuffer;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;

/**
 * Downstream ChannelHandler encoding AbstractResponseMessage objects
 * into ChannelBuffer objects.
 */
@Sharable
public class XrootdEncoder extends SimpleChannelHandler
{
    @Override
    public void writeRequested(ChannelHandlerContext ctx, MessageEvent e)
    {
        Object msg = e.getMessage();
        if (msg instanceof AbstractResponseMessage) {
            AbstractResponseMessage response =
                (AbstractResponseMessage) msg;
            ChannelBuffer buffer = response.getBuffer();
            buffer.setInt(4, buffer.readableBytes() - 8);
            msg = buffer;
        }
        write(ctx, e.getFuture(), msg);
    }
}
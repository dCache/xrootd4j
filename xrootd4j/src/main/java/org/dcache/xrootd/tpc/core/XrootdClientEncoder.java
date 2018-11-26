/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.core;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

import org.dcache.xrootd.tpc.XrootdTpcClient;
import org.dcache.xrootd.tpc.protocol.messages.XrootdOutboundRequest;

/**
 *  <p>Downstream ChannelHandler for translating {@link XrootdOutboundRequest}
 *      objects into xrootd ByteBuf objects.</p>
 *
 *  <p>Intended to support third-party client requests to a source server.</p>
 */
public class XrootdClientEncoder extends ChannelOutboundHandlerAdapter
{
    protected final XrootdTpcClient client;

    public XrootdClientEncoder(XrootdTpcClient client)
    {
        this.client = client;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg,
                      ChannelPromise promise)
                    throws Exception
    {
        if (msg instanceof XrootdOutboundRequest) {
            XrootdOutboundRequest request = (XrootdOutboundRequest) msg;
            request.writeTo(ctx, promise);
        } else {
            super.write(ctx, msg, promise);
        }
    }
}

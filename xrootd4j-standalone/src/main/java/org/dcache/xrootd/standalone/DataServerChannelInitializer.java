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
package org.dcache.xrootd.standalone;

import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.stream.ChunkedWriteHandler;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.EventExecutorGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.core.XrootdCodec;
import org.dcache.xrootd.core.XrootdHandshakeHandler;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;

import static org.dcache.xrootd.protocol.XrootdProtocol.DATA_SERVER;

public class DataServerChannelInitializer extends ChannelInitializer
{
    private static final Logger LOGGER = LoggerFactory.getLogger(DataServerChannelInitializer.class);

    private static final int THREADS = 16;

    private final EventExecutorGroup _eventExecutor = new DefaultEventExecutorGroup(THREADS);
    private final DataServerConfiguration _options;

    public DataServerChannelInitializer(DataServerConfiguration options)
    {
        _options = options;
    }

    @Override
    protected void initChannel(Channel ch) throws Exception
    {
        ch.pipeline().addLast("codec", new XrootdCodec());
        if (LOGGER.isDebugEnabled()) {
            ch.pipeline().addLast("logger", new LoggingHandler(DataServerChannelInitializer.class));
        }
        ch.pipeline().addLast("handshaker", new XrootdHandshakeHandler(DATA_SERVER));

        for (ChannelHandlerFactory factory: _options.channelHandlerFactories) {
            ch.pipeline().addLast("plugin:" + factory.getName(), factory.createHandler());
        }

        ch.pipeline().addLast(_eventExecutor, "chunk-writer", new ChunkedWriteHandler());
        ch.pipeline().addLast(_eventExecutor, "data-server", new DataServerHandler(_options));
    }
}

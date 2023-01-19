/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.standalone;

import static org.dcache.xrootd.protocol.XrootdProtocol.DATA_SERVER;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.logging.LoggingHandler;
import org.dcache.xrootd.core.XrootdDecoder;
import org.dcache.xrootd.core.XrootdEncoder;
import org.dcache.xrootd.core.XrootdHandshakeHandler;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.stream.ChunkedResponseWriteHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DataServerChannelInitializer extends ChannelInitializer<SocketChannel> {

    private static final Logger logger = LoggerFactory.getLogger(
          DataServerChannelInitializer.class);

    private final DataServerConfiguration _options;

    public DataServerChannelInitializer(DataServerConfiguration options) {
        _options = options;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();
        pipeline.addLast("handshaker", new XrootdHandshakeHandler(DATA_SERVER));
        pipeline.addLast("encoder", new XrootdEncoder());
        pipeline.addLast("decoder", new XrootdDecoder());
        if (logger.isDebugEnabled()) {
            pipeline.addLast("logger", new LoggingHandler(DataServerChannelInitializer.class));
        }

        for (ChannelHandlerFactory factory : _options.channelHandlerFactories) {
            pipeline.addLast("plugin:" + factory.getName(), factory.createHandler());
        }

        pipeline.addLast("chunk-writer", new ChunkedResponseWriteHandler());
        pipeline.addLast("data-server", new DataServerHandler(_options));
    }
}

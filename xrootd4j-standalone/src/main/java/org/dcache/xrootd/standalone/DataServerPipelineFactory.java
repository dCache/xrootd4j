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

import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.stream.ChunkedResponseWriteHandler;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.group.ChannelGroup;
import org.jboss.netty.handler.execution.ExecutionHandler;
import org.jboss.netty.handler.execution.OrderedMemoryAwareThreadPoolExecutor;
import org.jboss.netty.handler.logging.LoggingHandler;
import static org.jboss.netty.channel.Channels.pipeline;

import org.dcache.xrootd.core.XrootdEncoder;
import org.dcache.xrootd.core.XrootdDecoder;
import org.dcache.xrootd.core.XrootdHandshakeHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

public class DataServerPipelineFactory implements ChannelPipelineFactory
{
    private static final Logger logger = LoggerFactory.getLogger(DataServerPipelineFactory.class);

    private static final int MB = 1 << 20;
    private static final int THREADS = 16;
    private static final int CHANNEL_MEMORY = 16 * MB;
    private static final int TOTAL_MEMORY = 65 * MB;

    private final ExecutionHandler _executionHandler =
        new ExecutionHandler(new OrderedMemoryAwareThreadPoolExecutor(THREADS, CHANNEL_MEMORY, TOTAL_MEMORY));

    private final DataServerConfiguration _options;
    private final ChannelGroup _allChannels;

    public DataServerPipelineFactory(DataServerConfiguration options,
                                     ChannelGroup allChannels)
    {
        _options = options;
        _allChannels = allChannels;
    }

    @Override
    public ChannelPipeline getPipeline()
    {
        ChannelPipeline pipeline = pipeline();
        pipeline.addLast("encoder", new XrootdEncoder());
        pipeline.addLast("decoder", new XrootdDecoder());
        if (logger.isDebugEnabled()) {
            pipeline.addLast("logger", new LoggingHandler(DataServerPipelineFactory.class));
        }
        pipeline.addLast("handshaker", new XrootdHandshakeHandler(DATA_SERVER));

        for (ChannelHandlerFactory factory: _options.channelHandlerFactories) {
            pipeline.addLast("plugin:" + factory.getName(), factory.createHandler());
        }

        pipeline.addLast("executor", _executionHandler);
        pipeline.addLast("chunk-writer", new ChunkedResponseWriteHandler());
        pipeline.addLast("data-server",
                         new DataServerHandler(_options,
                                               _allChannels));
        return pipeline;
    }
}

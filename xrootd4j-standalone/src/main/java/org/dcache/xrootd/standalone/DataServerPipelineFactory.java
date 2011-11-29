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
package org.dcache.xrootd.standalone;

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
import org.dcache.xrootd.core.XrootdAuthenticationHandler;
import org.dcache.xrootd.core.XrootdAuthorizationHandler;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

public class DataServerPipelineFactory implements ChannelPipelineFactory
{
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
        pipeline.addLast("logger", new LoggingHandler(DataServer.class));
        pipeline.addLast("handshaker", new XrootdHandshakeHandler(DATA_SERVER));
        pipeline.addLast("authenticator", new XrootdAuthenticationHandler(_options.authenticationFactory));
        pipeline.addLast("authorizer", new XrootdAuthorizationHandler(_options.authorizationFactory));
        pipeline.addLast("executor", _executionHandler);
        pipeline.addLast("data-server",
                         new DataServerHandler(_options,
                                               _allChannels));
        return pipeline;
    }
}

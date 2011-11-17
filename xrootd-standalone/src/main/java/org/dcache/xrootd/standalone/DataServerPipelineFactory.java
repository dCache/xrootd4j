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
import static org.dcache.xrootd.protocol.XrootdProtocol.*;
import org.dcache.xrootd.security.AuthenticationFactory;
import org.dcache.xrootd.security.AuthorizationFactory;

public class DataServerPipelineFactory implements ChannelPipelineFactory
{
    private static final int MB = 1 << 20;
    private static final int THREADS = 16;
    private static final int CHANNEL_MEMORY = 16 * MB;
    private static final int TOTAL_MEMORY = 65 * MB;

    private final AuthenticationFactory _authenticationFactory =
        new org.dcache.xrootd.security.plugins.authn.none.NoAuthenticationFactory();
    private final AuthorizationFactory _authorizationFactory =
        new org.dcache.xrootd.security.plugins.authz.NoAuthorizationFactory();

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
        pipeline.addLast("handshake", new XrootdHandshakeHandler(DATA_SERVER));
        pipeline.addLast("executor", _executionHandler);
        pipeline.addLast("data-server",
                         new DataServerHandler(_options,
                                               _allChannels));
        return pipeline;
    }
}

#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import io.netty.channel.ChannelHandler;

public class PluginChannelHandlerFactory implements ChannelHandlerFactory
{
    final static String NAME = "${name}";

    final static Set<String> ALTERNATIVE_NAMES =
        new HashSet(Arrays.asList(NAME));

    static boolean hasName(String name)
    {
        return ALTERNATIVE_NAMES.contains(name);
    }

    @Override
    public String getName()
    {
        return NAME;
    }

    @Override
    public String getDescription()
    {
        return "${description}";
    }

    @Override
    public ChannelHandler createHandler()
    {
        return new PluginChannelHandler();
    }
}

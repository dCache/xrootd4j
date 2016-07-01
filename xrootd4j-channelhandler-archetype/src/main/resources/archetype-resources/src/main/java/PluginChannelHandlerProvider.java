#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.util.Properties;

import org.dcache.xrootd.plugins.ChannelHandlerProvider;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;

public class PluginChannelHandlerProvider implements ChannelHandlerProvider
{
    @Override
    public ChannelHandlerFactory
        createFactory(String plugin, Properties properties)
    {
        if (PluginChannelHandlerFactory.hasName(plugin)) {
            return new PluginChannelHandlerFactory();
        }
        return null;
    }
}
#set( $symbol_pound = '#' )
#set( $symbol_dollar = '$' )
#set( $symbol_escape = '\' )
package ${package};

import java.util.Properties;

import org.dcache.xrootd.plugins.AuthorizationProvider;
import org.dcache.xrootd.plugins.AuthorizationFactory;

public class PluginAuthorizationProvider implements AuthorizationProvider
{
    @Override
    public AuthorizationFactory
        createFactory(String plugin, Properties properties)
    {
        if (PluginAuthorizationFactory.hasName(plugin)) {
            return new PluginAuthorizationFactory();
        }
        return null;
    }
}

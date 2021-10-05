import java.util.Properties;
import org.dcache.xrootd.plugins.ChannelHandlerFactory;
import org.dcache.xrootd.plugins.ChannelHandlerProvider;

public class PluginChannelHandlerProvider implements ChannelHandlerProvider {

    @Override
    public ChannelHandlerFactory
    createFactory(String plugin, Properties properties) {
        if (PluginChannelHandlerFactory.hasName(plugin)) {
            return new PluginChannelHandlerFactory();
        }
        return null;
    }
}

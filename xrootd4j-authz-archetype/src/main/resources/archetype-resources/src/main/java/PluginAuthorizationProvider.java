import java.util.Properties;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.plugins.AuthorizationProvider;

public class PluginAuthorizationProvider implements AuthorizationProvider {

    @Override
    public AuthorizationFactory
    createFactory(String plugin, Properties properties) {
        if (PluginAuthorizationFactory.hasName(plugin)) {
            return new PluginAuthorizationFactory();
        }
        return null;
    }
}
